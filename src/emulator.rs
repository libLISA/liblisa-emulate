use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::mem::ManuallyDrop;
use std::ops::Range;
use std::path::PathBuf;

use liblisa::arch::{Arch, CpuState};
use liblisa::encoding::dataflows::{AccessKind, Dataflows};
use liblisa::encoding::Encoding;
use liblisa::instr::InstructionFilter;
use liblisa::semantics::default::computation::SynthesizedComputation;
use liblisa::state::{MemoryState, Permissions, SystemState};
use liblisa::Instruction;
use liblisa_enc::InferEncodingError;

#[derive(Clone, Debug, Default)]
pub struct Memories<T> {
    items: Vec<(u64, T)>,
}

pub trait Arraylike {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn data(&self, range: Range<usize>) -> &[u8];
    fn data_mut(&mut self, range: Range<usize>) -> &mut [u8];
}

impl Arraylike for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn data(&self, range: Range<usize>) -> &[u8] {
        &self[range]
    }

    fn data_mut(&mut self, range: Range<usize>) -> &mut [u8] {
        &mut self[range]
    }
}

impl Arraylike for Box<[u8]> {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn data(&self, range: Range<usize>) -> &[u8] {
        &self[range]
    }

    fn data_mut(&mut self, range: Range<usize>) -> &mut [u8] {
        &mut self[range]
    }
}

impl Arraylike for ManuallyDrop<Box<[u8]>> {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn data(&self, range: Range<usize>) -> &[u8] {
        &self[range]
    }

    fn data_mut(&mut self, range: Range<usize>) -> &mut [u8] {
        &mut self[range]
    }
}

impl<T: Arraylike> Memories<T> {
    pub fn new(items: impl Iterator<Item = (u64, T)>) -> Self {
        Memories {
            items: items.collect(),
        }
    }

    pub fn map(&mut self, addr: u64, data: T) {
        assert!(
            self.items
                .iter()
                .all(|(other_addr, other_data)| *other_addr >= addr + data.len() as u64
                    || addr >= other_addr + other_data.len() as u64)
        );
        self.items.push((addr, data));
    }

    pub fn contains_entire(&mut self, mut range: Range<u64>) -> bool {
        while !range.is_empty() {
            let addr = range.start;
            if let Some((_, memdata)) = self
                .items
                .iter_mut()
                .find(|(data_addr, data)| addr >= *data_addr && addr < data_addr + data.len() as u64)
            {
                let new_addr = addr + memdata.len() as u64;
                if new_addr >= range.end {
                    return true;
                } else {
                    range = new_addr..range.end;
                }
            } else {
                return false;
            }
        }

        true
    }

    pub fn write(&mut self, mut addr: u64, mut data: &[u8]) {
        while !data.is_empty() {
            if let Some((start, memdata)) = self
                .items
                .iter_mut()
                .find(|(data_addr, data)| addr >= *data_addr && addr < data_addr + data.len() as u64)
            {
                let offset = (addr - *start) as usize;
                let num_bytes = data.len().min(memdata.len());
                memdata
                    .data_mut(offset..offset + num_bytes)
                    .copy_from_slice(&data[..num_bytes]);

                addr += num_bytes as u64;
                data = &data[num_bytes..];
            } else {
                panic!(
                    "Tried to write unavailable memory: 0x{:X}..0x{:X}",
                    addr,
                    addr + data.len() as u64
                )
            }
        }
    }

    pub fn read(&self, mut addr: u64, mut data: &mut [u8]) {
        while !data.is_empty() {
            if let Some((start, memdata)) = self
                .items
                .iter()
                .find(|(data_addr, data)| addr >= *data_addr && addr < data_addr + data.len() as u64)
            {
                let offset = (addr - *start) as usize;
                let num_bytes = data.len().min(memdata.len());
                data[..num_bytes].copy_from_slice(memdata.data(offset..offset + num_bytes));

                addr += num_bytes as u64;
                data = &mut data[num_bytes..];
            } else {
                panic!(
                    "Tried to read unavailable memory: 0x{:X}..0x{:X}",
                    addr,
                    addr + data.len() as u64
                )
            }
        }
    }

    pub fn read_while(&self, mut addr: u64, mut cond: impl FnMut(u8) -> bool, data: &mut Vec<u8>) {
        let mut b = [0u8; 1];
        loop {
            self.read(addr, &mut b);
            if cond(b[0]) {
                data.push(b[0]);
            } else {
                return
            }

            addr += 1;
        }
    }
}

pub trait Backend<A: Arch, T> {
    fn infer_encoding(&mut self, instr: &Instruction) -> Result<Encoding<A, SynthesizedComputation>, InferEncodingError>;

    fn syscall(&mut self, state: &mut A::CpuState, memory: &mut Memories<T>);
    fn cpuid(&mut self, _state: &mut A::CpuState) {}
    fn xgetbv(&mut self, _state: &mut A::CpuState) {}

    fn trace_match(&mut self, _instr: &Instruction, _encoding: &Encoding<A, SynthesizedComputation>) {}
    fn trace_pre_execute(&mut self, _instance: &Dataflows<A, SynthesizedComputation>, _state: &SystemState<A>) {}
    fn trace_post_execute(&mut self, _instance: &Dataflows<A, SynthesizedComputation>, _state: &SystemState<A>) {}
}

pub enum FilterMatch<T> {
    Found(T),
    InstructionTooShort,
    NotFound,
}

#[derive(Clone, Debug)]
pub struct FilterMap<T> {
    filters: [Vec<(InstructionFilter, T)>; 256],
}

impl<T: Clone + std::fmt::Debug> FilterMap<T> {
    pub fn new() -> FilterMap<T> {
        FilterMap {
            filters: vec![Vec::new(); 256].try_into().unwrap(),
        }
    }

    pub fn add(&mut self, filter: InstructionFilter, data: T) {
        let b = &filter.data[0];

        for index in 0..256 {
            if b.matches(index as u8) {
                self.filters[index].push((filter.clone(), data.clone()));
            }
        }
    }

    pub fn find(&self, instruction: &Instruction) -> FilterMatch<&T> {
        for (filter, data) in self.filters[instruction.bytes()[0] as usize].iter() {
            if filter.len() == instruction.byte_len() && filter.matches(instruction) {
                return FilterMatch::Found(data);
            } else if filter.matches_smaller_instr_partially(instruction) {
                return FilterMatch::InstructionTooShort;
            }
        }

        FilterMatch::NotFound
    }
}

impl<T: Clone + std::fmt::Debug> Default for FilterMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Emulator<A: Arch, T, B: Backend<A, T>> {
    cpu: A::CpuState,
    memory: Memories<T>,
    backend: B,
    encoding_cache_path: Option<PathBuf>,
    encoding_cache: Vec<Encoding<A, SynthesizedComputation>>,
    filter_map: FilterMap<usize>,
}

impl<A: Arch, T: Arraylike, B: Backend<A, T>> Emulator<A, T, B> {
    pub fn new(
        memory: Memories<T>, cpu: A::CpuState, encoding_cache_path: Option<PathBuf>, backend: B,
    ) -> Result<Self, io::Error> {
        let (encoding_cache, filter_map) = if let Some(path) = &encoding_cache_path {
            let file = File::options().create(true).append(true).read(true).open(path)?;
            let mut encoding_cache = Vec::new();
            let mut filter_map = FilterMap::new();
            for line in BufReader::new(file).lines() {
                let line = line?;
                match serde_json::from_str::<Encoding<A, SynthesizedComputation>>(&line) {
                    Ok(encoding) => {
                        for filter in encoding.filters() {
                            filter_map.add(filter, encoding_cache.len());
                        }

                        encoding_cache.push(encoding);
                    },
                    Err(e) => {
                        panic!("Invalid JSON {e}: {line}");
                    },
                }
            }

            (encoding_cache, filter_map)
        } else {
            Default::default()
        };

        Ok(Emulator {
            memory,
            cpu,
            backend,
            encoding_cache,
            filter_map,
            encoding_cache_path,
        })
    }

    pub fn add_encoding(&mut self, encoding: Encoding<A, SynthesizedComputation>) {
        for filter in encoding.filters() {
            self.filter_map.add(filter, self.encoding_cache.len());
        }

        self.encoding_cache.push(encoding);
    }

    pub fn find_encoding(
        &mut self, instr: &Instruction,
    ) -> Option<Result<Encoding<A, SynthesizedComputation>, InferEncodingError>> {
        match self.filter_map.find(instr) {
            FilterMatch::Found(index) => Some(Ok(self.encoding_cache[*index].clone())),
            FilterMatch::InstructionTooShort => Some(Err(InferEncodingError::TooShort)),
            FilterMatch::NotFound => None,
        }
    }

    pub fn find_or_infer_encoding(
        &mut self, instr: &Instruction,
    ) -> Result<Encoding<A, SynthesizedComputation>, InferEncodingError> {
        if let Some(result) = self.find_encoding(instr) {
            return result;
        }

        let semantics = self.backend.infer_encoding(instr)?;
        if !semantics.all_outputs_have_computations() {
            panic!("Missing computations for some outputs: {semantics}");
        }

        if let Some(path) = &self.encoding_cache_path {
            let file = File::options().append(true).create(true).open(path).unwrap();
            let mut file = BufWriter::new(file);
            serde_json::to_writer(&mut file, &semantics).unwrap();
            writeln!(&mut file).unwrap();
        }

        self.add_encoding(semantics.clone());

        Ok(semantics)
    }

    pub fn run(&mut self) {
        const SKIP_PREFIXES: &[Instruction] = &[
            Instruction::new(&[0x0f]),
            Instruction::new(&[0x0f, 0x01]),
            Instruction::new(&[0x4f]),
            Instruction::new(&[0x4f, 0x45]),
            Instruction::new(&[0x0F, 0xC7]),
            Instruction::new(&[0x0F, 0xC7, 0x64]),
            Instruction::new(&[0x0F, 0xC7, 0x64, 0x24]),
            Instruction::new(&[0x0F, 0xAE]),
            Instruction::new(&[0x0F, 0xAE, 0x6C]),
            Instruction::new(&[0x0F, 0xAE, 0x6C, 0x24]),
        ];
        const EXIT_INSTR: Instruction = Instruction::new(&[0x06]);
        const SYSCALL_INSTR: Instruction = Instruction::new(&[0x0f, 0x05]);
        const CPUID_INSTR: Instruction = Instruction::new(&[0x0f, 0xa2]);
        const XGETBV_INSTR: Instruction = Instruction::new(&[0x0f, 0x01, 0xD0]);
        const NOP_INSTRS: &[Instruction] = &[
            // ICEBP
            Instruction::new(&[0x4f, 0x45, 0xf1]),
            // RDTSC
            Instruction::new(&[0x0f, 0x31]),
            // TODO: we *should* implement XSAVEC, but everything seems to work if we just ignore it
            Instruction::new(&[0x0F, 0xC7, 0x64, 0x24, 0x40]),
            // TODO: we *should* implement XRSTOR, but everything seems to work if we just ignore it
            Instruction::new(&[0x0F, 0xAE, 0x6C, 0x24, 0x40]),
        ];

        loop {
            let rip = self.cpu.gpreg(A::PC);
            for len in 1..16 {
                let mut instr_data = [0; 16];
                let instr_data = &mut instr_data[..len];
                self.memory.read(rip, instr_data);
                let instr = Instruction::new(instr_data);
                if instr == EXIT_INSTR {
                    return
                } else if instr == SYSCALL_INSTR {
                    self.cpu.set_gpreg(A::PC, rip.wrapping_add(instr.byte_len() as u64));
                    self.backend.syscall(&mut self.cpu, &mut self.memory);
                    break
                } else if instr == CPUID_INSTR {
                    self.cpu.set_gpreg(A::PC, rip.wrapping_add(instr.byte_len() as u64));
                    self.backend.cpuid(&mut self.cpu);
                    break
                } else if instr == XGETBV_INSTR {
                    self.cpu.set_gpreg(A::PC, rip.wrapping_add(instr.byte_len() as u64));
                    self.backend.xgetbv(&mut self.cpu);
                    break
                } else if NOP_INSTRS.contains(&instr) {
                    self.cpu.set_gpreg(A::PC, rip.wrapping_add(instr.byte_len() as u64));
                    break
                } else if SKIP_PREFIXES.contains(&instr) {
                    continue
                } else {
                    match self.find_or_infer_encoding(&instr) {
                        Ok(encoding) => {
                            self.backend.trace_match(&instr, &encoding);

                            let part_values = encoding.extract_parts(&instr);
                            let instance = encoding.instantiate(&part_values).unwrap();
                            let state = SystemState::new_without_memory(self.cpu.clone());
                            let mut mem = Vec::with_capacity(instance.addresses.len());
                            for (area, access) in instance.extract_memory_areas(&state).zip(instance.addresses.iter()) {
                                let mut data = vec![0; area.size() as usize];
                                self.memory.read(area.start_addr().as_u64(), &mut data);
                                mem.push((
                                    area.start_addr(),
                                    match access.kind {
                                        AccessKind::Input => Permissions::Read,
                                        AccessKind::InputOutput => Permissions::ReadWrite,
                                        AccessKind::Executable => Permissions::Execute,
                                    },
                                    data,
                                ));
                            }

                            let mut state = state.with_new_memory(mem.len(), 1, MemoryState::from_vec(mem.clone()));

                            self.backend.trace_pre_execute(&instance, &state);
                            instance.execute(&mut state);
                            self.backend.trace_post_execute(&instance, &state);

                            for ((addr, perms, data), (_, _, old_data)) in state.memory().iter().zip(mem.iter()) {
                                if *perms == Permissions::ReadWrite && old_data != data {
                                    self.memory.write(addr.as_u64(), data);
                                }
                            }

                            self.cpu = state.cpu().clone();
                            break;
                        },
                        Err(InferEncodingError::TooShort) => continue,
                        _ => unreachable!(),
                    }
                }
            }
        }
    }
}
