use std::iter::once;
use std::path::PathBuf;

use clap::Parser;
use liblisa::arch::x64::{X64Arch, X64State};
use liblisa::encoding::dataflows::Dataflows;
use liblisa::encoding::Encoding;
use liblisa::oracle::Oracle;
use liblisa::semantics::default::computation::SynthesizedComputation;
use liblisa::state::{Permissions, SystemState};
use liblisa::Instruction;
use liblisa_emulate::emulator::*;
use liblisa_emulate::hex::HexData;
use liblisa_enc::{infer_encoding, InferEncodingError};
use liblisa_libcli::threadpool::cpu::CpuCaches;
use liblisa_libcli::StateSpecArgs;
use liblisa_synth::{prepare_templates, synthesize_semantics};
use liblisa_x64_observer::with_oracle;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(clap::Parser)]
struct Args {
    #[clap(long)]
    cache: Option<PathBuf>,

    bytes: HexData,

    #[clap(flatten)]
    state_spec: StateSpecArgs,
}

struct SimpleBackend<'a, O: Oracle<X64Arch>> {
    oracle: &'a mut O,
}

impl<'a, O: Oracle<X64Arch>, T: Arraylike> Backend<X64Arch, T> for SimpleBackend<'a, O> {
    fn infer_encoding(&mut self, instr: &Instruction) -> Result<Encoding<X64Arch, SynthesizedComputation>, InferEncodingError> {
        println!("Missing encoding for: {instr:X}");

        let mut encoding = infer_encoding(instr, self.oracle)?;
        println!("Encoding: {encoding}");

        encoding.split_flag_output();

        // Do the work to const-expand the templates upfront, so it doesn't count against the synthesis time.
        println!("Preparing templates...");
        prepare_templates();
        println!("Templates prepared!");

        let semantics = synthesize_semantics(encoding, self.oracle);
        println!("Semantics: {semantics}");

        Ok(semantics)
    }

    fn syscall(&mut self, _state: &mut X64State, _memory: &mut Memories<T>) {
        unimplemented!("Please use elf-emulate if you need syscalls")
    }

    fn trace_match(&mut self, instr: &Instruction, encoding: &Encoding<X64Arch, SynthesizedComputation>) {
        eprintln!("Matched {instr:X} to encoding: {encoding}")
    }

    fn trace_pre_execute(&mut self, instance: &Dataflows<X64Arch, SynthesizedComputation>, state: &SystemState<X64Arch>) {
        eprintln!("Instantiated: {instance}");
        eprintln!("Before execution: {state:X?}");
    }

    fn trace_post_execute(&mut self, _instance: &Dataflows<X64Arch, SynthesizedComputation>, state: &SystemState<X64Arch>) {
        eprintln!("After execution: {state:X?}");
    }
}

pub fn main() {
    env_logger::init();
    let cpu = CpuCaches::from_path("/sys/devices/system/cpu/cpu0/cache").unwrap();
    // Restrict the current thread to only run on cores that share L3 cache.
    let cache = cpu.caches().find(|c| c.level() == 3).unwrap();
    println!("Restricting affinity to CPUs that share {cache:#?}");
    cache.restrict_current_thread_affinity_to_shared_caches().unwrap();

    let args = Args::parse();
    let program_memory = Vec::from(args.bytes).into_boxed_slice();
    let state: SystemState<X64Arch> = args.state_spec.create_state(Instruction::new(&[0x06]), 0);
    let memory = Memories::new(
        once((0, program_memory)).chain(
            state
                .memory()
                .iter()
                .filter(|&&(_, perms, _)| perms != Permissions::Execute)
                .map(|(addr, _, data)| (addr.as_u64(), data.clone().into_boxed_slice())),
        ),
    );

    with_oracle(|mut oracle| {
        let mut emu = Emulator::new(
            memory,
            state.cpu().clone(),
            args.cache,
            SimpleBackend {
                oracle: &mut oracle,
            },
        )
        .unwrap();
        emu.run();
    })
}
