use std::arch::asm;
use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::BufReader;
use std::iter::once;
use std::mem::ManuallyDrop;
use std::os::unix::prelude::OsStrExt;
use std::path::PathBuf;
use std::ptr::null_mut;

use elfloader::{ElfBinary, ElfLoader, ElfLoaderErr, ProgramHeader, RelocationType};
use libc::{
    c_uint, c_void, termios, winsize, SYS_fadvise64, SYS_futex, SYS_getdents64, MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE,
    MAP_PRIVATE, PROT_READ, PROT_WRITE, TCGETS, TIOCGWINSZ,
};
use liblisa::arch::x64::{GpReg, X64Arch, X64State};
use liblisa::arch::{Arch, CpuState};
use liblisa::encoding::dataflows::Dataflows;
use liblisa::encoding::Encoding;
use liblisa::oracle::Oracle;
use liblisa::semantics::default::computation::SynthesizedComputation;
use liblisa::state::SystemState;
use liblisa::Instruction;
use liblisa_emulate::emulator::*;
use liblisa_enc::{infer_encoding, InferEncodingError};
use liblisa_libcli::threadpool::cpu::CpuCaches;
use liblisa_synth::{prepare_templates, synthesize_semantics};
use liblisa_x64_observer::with_oracle;

type A = X64Arch;

use clap::Parser;
use log::info;
use rand::prelude::*;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(clap::Parser)]
struct Args {
    #[clap(long)]
    cache: Option<PathBuf>,

    #[clap(long)]
    semantics: Vec<PathBuf>,

    #[clap(long)]
    trace_execution: bool,

    #[clap(long)]
    trace_execution_delay: Option<usize>,

    #[clap(long)]
    trace_syscalls: bool,

    #[clap(long)]
    trace_rip: bool,

    #[clap(long)]
    cross_check: bool,

    binary: PathBuf,

    args: Vec<String>,

    #[clap(long)]
    interpreter_override: Option<String>,

    #[clap(long)]
    vbase: Option<String>,

    #[clap(long)]
    interp_vbase: Option<String>,

    #[clap(long)]
    openat_remap: Vec<String>,
}

struct Loader {
    vbase: u64,

    // TODO: This is unsafe and undefined behavior in every possible way. Just use a (*mut u8, usize) tuple instead...
    memories: Memories<ManuallyDrop<Box<[u8]>>>,
}

struct ElfBackend<'a, O: Oracle<A>> {
    oracle: &'a mut O,
    trace_execution: bool,
    trace_syscalls: bool,
    trace_rip: bool,
    cross_check: bool,
    trace_delay: usize,
    instruction_count: usize,
    expected_output_state: Option<SystemState<A>>,
    openat_remap: HashMap<String, CString>,
}

impl<'a, O: Oracle<A>> Backend<A, ManuallyDrop<Box<[u8]>>> for ElfBackend<'a, O> {
    fn infer_encoding(&mut self, instr: &Instruction) -> Result<Encoding<A, SynthesizedComputation>, InferEncodingError> {
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

    fn syscall(&mut self, state: &mut X64State, memory: &mut Memories<ManuallyDrop<Box<[u8]>>>) {
        let num = CpuState::<A>::gpreg(state, GpReg::Rax);
        let a = CpuState::<A>::gpreg(state, GpReg::Rdi);
        let mut b = CpuState::<A>::gpreg(state, GpReg::Rsi);
        let c = CpuState::<A>::gpreg(state, GpReg::Rdx);
        let d = CpuState::<A>::gpreg(state, GpReg::R10);
        let e = CpuState::<A>::gpreg(state, GpReg::R8);
        let f = CpuState::<A>::gpreg(state, GpReg::R9);

        let name = match num {
            0 => "read",
            1 => "write",
            3 => "close",
            8 => "lseek",
            9 => "mmap",
            10 => "mprotect",
            11 => "munmap",
            12 => "brk",
            13 => "rt_sigaction",
            14 => "rt_sigprocmask",
            16 => "ioctl",
            17 => "pread64",
            20 => "writev",
            21 => "access",
            41 => "socket",
            42 => "connect",
            44 => "sendto",
            45 => "recvfrom",
            60 => "exit",
            63 => "uname",
            72 => "fcntl",
            99 => "sysinfo",
            102 => "getuid",
            104 => "getgid",
            107 => "geteuid",
            108 => "getegid",
            137 => "statfs",
            158 => "arch_prctl",
            186 => "gettid",
            191 => "time",
            192 => "lgetxattr",
            202 => "futex",
            204 => "sched_getaffinity",
            217 => "getdents64",
            218 => "set_tid_address",
            221 => "fadvise",
            228 => "clock_gettime",
            231 => "exit_group",
            257 => "openat",
            262 => "newfstatat",
            273 => "set_robust_list",
            302 => "prlimit64",
            318 => "getrandom",
            332 => "statx",
            334 => "rseq",
            _ => "<unknown>",
        };

        if self.trace_syscalls {
            let mut a_data = Vec::new();
            let a_as_str = if [137, 192].contains(&num) {
                memory.read_while(a, |b| b != 0, &mut a_data);
                std::str::from_utf8(&a_data).unwrap_or("")
            } else {
                ""
            };

            let mut b_data = Vec::new();
            let b_as_str = if [257, 192].contains(&num) {
                memory.read_while(b, |b| b != 0, &mut b_data);
                std::str::from_utf8(&b_data).unwrap_or("")
            } else {
                ""
            };

            println!("syscall[{num}/{name}](0x{a:X} {a_as_str}, 0x{b:X} {b_as_str}, 0x{c:X}, 0x{d:X}, 0x{e:X}, 0x{f:X})");

            if let Some(remap) = self.openat_remap.get(b_as_str) {
                println!("  [!] remapping {b_as_str} to {remap:?}");
                b = remap.as_ptr() as u64;
            }
        }

        // const ARCH_SET_FS: u64 =
        const ARCH_CET_STATUS: u64 = 0x3001;
        const MAP_FIXED: u64 = libc::MAP_FIXED as u64;
        const MAP_FIXED_NOREPLACE: u64 = libc::MAP_FIXED_NOREPLACE as u64;
        const ARCH_SET_GS: u64 = 0x1001;
        const ARCH_SET_FS: u64 = 0x1002;
        const ARCH_GET_FS: u64 = 0x1003;
        const ARCH_GET_GS: u64 = 0x1004;

        let ret = match num {
            0 => unsafe { libc::read(a as _, b as _, c as _) as u64 },
            1 => unsafe { libc::write(a as _, b as _, c as _) as u64 },
            3 => unsafe { libc::close(a as _) as u64 },
            8 => unsafe { libc::lseek(a as _, b as _, c as _) as u64 },
            9 => {
                let addr = a;
                let length = b;
                let prot = c;
                let flags = d;
                let fd = e;
                let offset = f;

                let needs_new_entry = if flags & MAP_FIXED != 0 || flags & MAP_FIXED_NOREPLACE != 0 {
                    if memory.contains_entire(addr..addr + length) {
                        false
                    } else {
                        panic!("MAP_FIXED not implemented");
                    }
                } else {
                    true
                };

                let ptr = unsafe { libc::mmap(addr as _, length as _, prot as _, flags as _, fd as _, offset as _) };
                if needs_new_entry {
                    let v = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(ptr as *mut u8, length as usize)) };

                    memory.map(ptr as u64, ManuallyDrop::new(v));
                }

                ptr as u64
            },
            10 => unsafe { libc::mprotect(a as _, b as _, c as _) as u64 },
            11 => {
                // Cheat our way through munmap
                0
            },
            12 => {
                if a == 0 {
                    // Try to cheat our way through the syscall by just returning 0...
                    0
                } else {
                    // TODO: Need a wrapper for sys_brk -- we'll just fail for now...
                    u64::MAX
                }
            },
            13 => {
                // Cheat our way through rt_sigaction by just returning success
                0
            },
            14 => {
                // Cheat our way through rt_sigprocmask by just returning success
                0
            },
            16 => unsafe {
                match b {
                    TCGETS => libc::ioctl(a as _, b as _, c as *mut termios) as u64,
                    TIOCGWINSZ => libc::ioctl(a as _, b as _, c as *mut winsize) as u64,
                    req => panic!("ioctl request 0x{req:X} not implemented"),
                }
            },
            17 => unsafe { libc::pread64(a as _, b as _, c as _, d as _) as u64 },
            20 => unsafe { libc::writev(a as _, b as _, c as _) as u64 },
            21 => unsafe { libc::access(a as _, b as _) as u64 },
            41 => unsafe { libc::socket(a as _, b as _, c as _) as u64 },
            42 => unsafe { libc::connect(a as _, b as _, c as _) as u64 },
            44 => unsafe { libc::sendto(a as _, b as _, c as _, d as _, e as _, f as _) as u64 },
            45 => unsafe { libc::recvfrom(a as _, b as _, c as _, d as _, e as _, f as _) as u64 },
            60 => unsafe { libc::exit(a as _) },
            63 => unsafe { libc::uname(a as _) as u64 },
            72 => unsafe { libc::fcntl(a as _, b as _) as u64 },
            99 => unsafe { libc::sysinfo(a as _) as u64 },
            102 => unsafe { libc::getuid() as u64 },
            104 => unsafe { libc::getgid() as u64 },
            107 => unsafe { libc::geteuid() as u64 },
            108 => unsafe { libc::getegid() as u64 },
            137 => unsafe { libc::statfs(a as _, b as _) as u64 },
            158 => match a {
                ARCH_CET_STATUS => u64::MAX,
                ARCH_SET_GS => {
                    CpuState::<A>::set_gpreg(state, GpReg::GsBase, b);
                    0
                },
                ARCH_SET_FS => {
                    CpuState::<A>::set_gpreg(state, GpReg::FsBase, b);
                    0
                },
                ARCH_GET_FS => CpuState::<A>::gpreg(state, GpReg::FsBase),
                ARCH_GET_GS => CpuState::<A>::gpreg(state, GpReg::GsBase),
                _ => panic!("arch_prctl({a}) not implemented"),
            },
            186 => {
                // Cheat our way through gettid
                0x42
            },
            191 => unsafe { libc::time(a as _) as u64 },
            192 => unsafe { libc::lgetxattr(a as _, b as _, c as _, d as _) as u64 },
            202 => unsafe { libc::syscall(SYS_futex, a, b, c, d, e, f) as u64 },
            204 => unsafe { libc::sched_getaffinity(a as _, b as _, c as _) as u64 },
            217 => unsafe { libc::syscall(SYS_getdents64, a as c_uint, b as *mut c_void, c as c_uint) as u64 },
            218 => {
                // Cheat our way through set_tid_address
                0x42
            },
            221 => unsafe { libc::syscall(SYS_fadvise64, a, b, c, d) as u64 },
            228 => unsafe { libc::clock_gettime(a as _, b as _) as u64 },
            // TODO: Does libc expose a separate exit vs exit_group?
            231 => unsafe { libc::exit(a as _) },
            257 => unsafe { libc::openat(a as _, b as _, c as _, d as libc::mode_t) as u64 },
            262 => unsafe { libc::fstatat(a as _, b as _, c as _, d as _) as u64 },
            273 => {
                // Cheat our way through set_robust_list
                0
            },
            302 => unsafe { libc::prlimit64(a as _, b as _, c as _, d as _) as u64 },
            318 => {
                let bufptr = a;
                let buflen = b;

                let mut data = vec![0u8; buflen as usize];
                rand::thread_rng().fill_bytes(&mut data);

                memory.write(bufptr, &data);

                buflen
            },
            332 => unsafe { libc::statx(a as _, b as _, c as _, d as _, e as _) as u64 },
            334 => {
                // Cheat our way through rseq
                u64::MAX
            },
            other => panic!("Syscall not implemented: {other}"),
        };

        let ret = if ret == u64::MAX {
            let err = std::io::Error::last_os_error();

            if err.raw_os_error() != Some(0) {
                let raw_error = err.raw_os_error().unwrap();
                if self.trace_syscalls {
                    println!("    => ERROR ({raw_error}): {err}");
                }

                (-raw_error) as u64
            } else {
                ret
            }
        } else {
            ret
        };

        if self.trace_syscalls {
            println!("syscall[{num}/{name}] result = 0x{ret:X}");
        }

        CpuState::<A>::set_gpreg(state, GpReg::Rax, ret as i64 as u64);
    }

    fn trace_match(&mut self, instr: &Instruction, encoding: &Encoding<A, SynthesizedComputation>) {
        if self.trace_execution && self.trace_delay == 0 {
            eprintln!("Matched {instr:X} to encoding: {encoding}");
        }
    }

    fn trace_pre_execute(&mut self, instance: &Dataflows<A, SynthesizedComputation>, state: &SystemState<A>) {
        if self.trace_rip {
            eprintln!(
                "RIP = 0x{:16X}, instructions executed: {}",
                CpuState::<A>::gpreg(state.cpu(), GpReg::Rip),
                self.instruction_count
            );
        }

        if self.trace_execution {
            if self.trace_delay == 0 {
                eprintln!("Instantiated: {instance}");
                eprintln!("Before execution: {state:X?}");
            } else {
                self.trace_delay -= 1;
            }
        }

        if self.cross_check {
            if state.memory().areas().all(|a| !a.crosses_page_bounds(12)) {
                let mut state = state.clone();
                state.use_trap_flag = true;
                self.expected_output_state = Some(self.oracle.observe(&state).unwrap());
            } else {
                eprintln!("Can't observe output state because the memory accesses cross page bounds: {state:X?}");
                self.expected_output_state = None;
            }
        }
    }

    fn trace_post_execute(&mut self, _instance: &Dataflows<A, SynthesizedComputation>, state: &SystemState<A>) {
        self.instruction_count += 1;
        if self.trace_execution {
            eprintln!(
                "Instructions executed: {} @ 0x{:X}",
                self.instruction_count,
                CpuState::<A>::gpreg(state.cpu(), GpReg::Rip)
            );
            if self.trace_delay == 0 {
                eprintln!("After execution: {state:X?}");
            }
        }

        if let Some(expected_output_state) = self.expected_output_state.take() {
            assert_eq!(
                state, &expected_output_state,
                "Execution (left) must match observation (right)"
            );
        }
    }

    fn cpuid(&mut self, state: &mut <A as Arch>::CpuState) {
        let mut eax = CpuState::<A>::gpreg(state, GpReg::Rax);
        let mut ecx = CpuState::<A>::gpreg(state, GpReg::Rcx);
        let ebx: u64;
        let edx: u64;
        unsafe {
            asm!(
                "push rbx",
                "cpuid",
                "mov r11, rbx",
                "pop rbx",
                inout("eax") eax,
                inout("ecx") ecx,
                out("r11") ebx,
                out("edx") edx,
            );
        }
        CpuState::<A>::set_gpreg(state, GpReg::Rax, eax);
        CpuState::<A>::set_gpreg(state, GpReg::Rbx, ebx);
        CpuState::<A>::set_gpreg(state, GpReg::Rcx, ecx);
        CpuState::<A>::set_gpreg(state, GpReg::Rdx, edx);
    }

    fn xgetbv(&mut self, state: &mut <A as Arch>::CpuState) {
        let ecx = CpuState::<A>::gpreg(state, GpReg::Rcx);
        let eax: u64;
        let edx: u64;
        unsafe {
            asm!(
                "xgetbv",
                in("ecx") ecx,
                out("eax") eax,
                out("edx") edx,
            );
        }
        CpuState::<A>::set_gpreg(state, GpReg::Rax, eax);
        CpuState::<A>::set_gpreg(state, GpReg::Rdx, edx);
    }
}

impl Loader {
    fn allocate_anywhere(&mut self, length: usize) -> u64 {
        let (addr, data) = unsafe {
            let ptr = libc::mmap64(null_mut(), length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            let addr = ptr as u64;

            (addr, Vec::from_raw_parts(ptr as *mut u8, length, length))
        };
        info!(
            "Allocating: 0x{:X}..0x{:X} (length=0x{:X})",
            addr,
            addr + length as u64,
            length
        );
        self.memories.map(addr, ManuallyDrop::new(data.into_boxed_slice()));
        info!("Allocation done!");
        addr
    }
}

impl ElfLoader for Loader {
    fn allocate<'a>(&mut self, load_headers: impl Iterator<Item = ProgramHeader<'a>>) -> Result<(), elfloader::ElfLoaderErr> {
        for header in load_headers {
            info!("{header:?}");
            info!("Type: {:?}", header.get_type());

            let page_bits = (1 << 12) - 1;
            let addr = header.virtual_addr() + self.vbase;
            let start = addr & !page_bits;
            let length = header.mem_size();
            let end = (addr + length + page_bits) & !page_bits;
            let length = (end - start) as usize;

            info!(
                "Allocating: 0x{:X}..0x{:X} (length=0x{:X}) as 0x{:X}..0x{:X}",
                addr,
                addr + length as u64,
                length,
                start,
                end
            );

            let data = unsafe {
                let ptr = libc::mmap64(
                    start as _,
                    length,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                );

                assert_eq!(
                    ptr as u64, start,
                    "Unable to allocate memory at 0x{start:X}..0x{end:X} (length=0x{length:X})"
                );

                Vec::from_raw_parts(ptr as *mut u8, length, length)
            };
            self.memories.map(start, ManuallyDrop::new(data.into_boxed_slice()));
            info!("Allocation done!");
        }

        Ok(())
    }

    fn load(&mut self, _flags: elfloader::Flags, base: elfloader::VAddr, region: &[u8]) -> Result<(), elfloader::ElfLoaderErr> {
        let start = self.vbase + base;
        let end = self.vbase + base + region.len() as u64;
        info!("load region into = {start:#x} -- {end:#x}");

        self.memories.write(start, region);

        Ok(())
    }

    fn relocate(&mut self, entry: elfloader::RelocationEntry) -> Result<(), elfloader::ElfLoaderErr> {
        use elfloader::arch::x86_64::RelocationTypes::*;
        use RelocationType::x86_64;

        let addr: *mut u64 = (self.vbase + entry.offset) as *mut u64;

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                // This type requires addend to be present
                let addend = entry.addend.ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // This is a relative relocation, add the offset (where we put our
                // binary in the vspace) to the addend and we're done.
                info!("R_RELATIVE *{:p} = {:#x}", addr, self.vbase + addend);

                let mut data = [0u8; 8];
                self.memories.read(addr as u64, &mut data);
                info!("Current memory data: {data:02X?}");

                let new_data = (self.vbase + addend).to_le_bytes();
                info!("New memory data: {data:02X?}");

                self.memories.write(addr as u64, &new_data);

                Ok(())
            },
            other => {
                println!("TODO: {other:?}");
                Ok(())
            },
        }
    }
}

struct Stack<'a, T> {
    memories: &'a mut Memories<T>,
    rsp: u64,
}

impl<'a, T: Arraylike> Stack<'a, T> {
    pub fn push_u64(&mut self, data: u64) -> u64 {
        self.rsp -= 8;
        self.memories.write(self.rsp, &data.to_le_bytes());

        self.rsp
    }

    pub fn push_pair(&mut self, a: u64, b: u64) -> u64 {
        self.push_u64(b);
        self.push_u64(a)
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> u64 {
        self.rsp -= bytes.len() as u64;
        self.memories.write(self.rsp, bytes);

        self.rsp
    }

    pub fn push_cstr(&mut self, str: &str) -> u64 {
        let bytes = str.as_bytes();
        let total = bytes.iter().copied().chain(once(0)).collect::<Vec<_>>();

        self.push_bytes(&total)
    }

    pub fn push_osstr(&mut self, str: &OsStr) -> u64 {
        let bytes = str.as_bytes();
        let total = bytes.iter().copied().chain(once(0)).collect::<Vec<_>>();

        self.push_bytes(&total)
    }

    pub fn align_down(&mut self, alignment: u64) {
        self.rsp &= !((1 << alignment) - 1);
    }
}

pub fn main() {
    env_logger::init();
    let args = Args::parse();
    let cpu = CpuCaches::from_path("/sys/devices/system/cpu/cpu0/cache").unwrap();
    // Restrict the current thread to only run on cores that share L3 cache.
    let cache = cpu.caches().find(|c| c.level() == 3).unwrap();
    println!("Restricting affinity to CPUs that share {cache:#?}");
    cache.restrict_current_thread_affinity_to_shared_caches().unwrap();

    let mut state: SystemState<A> = SystemState::new_without_memory(Default::default());
    let mut loader = Loader {
        vbase: args
            .vbase
            .map(|s| u64::from_str_radix(&s, 16).unwrap())
            .unwrap_or(0x1eaf_0000_0000),
        memories: Memories::new([].into_iter()),
    };

    let binary_blob = fs::read(&args.binary).unwrap();
    let binary = ElfBinary::new(binary_blob.as_slice()).unwrap();
    println!("Loading binary...");
    binary.load(&mut loader).unwrap();

    let phdr = binary
        .program_headers()
        .find(|h| h.get_type() == Ok(xmas_elf::program::Type::Phdr))
        .map(|h| h.virtual_addr() + loader.vbase);

    let entry_point = binary.entry_point() + loader.vbase;

    // Set up stack
    let stack_size = 0x1_0000;
    let stack_base = loader.allocate_anywhere(stack_size);
    let mut stack = Stack {
        memories: &mut loader.memories,
        rsp: stack_base + stack_size as u64,
    };

    let mut rng = rand::thread_rng();
    let at_execfn = stack.push_cstr("./program");
    let at_platform = stack.push_cstr("x86-64");

    let argv = once(stack.push_osstr(args.binary.as_os_str()))
        .chain(args.args.iter().map(|arg| stack.push_cstr(arg)))
        .collect::<Vec<_>>();

    stack.align_down(4);

    let mut random_buffer = [0u8; 16];
    rng.fill_bytes(&mut random_buffer);
    let at_random = stack.push_bytes(&random_buffer);
    stack.align_down(12);

    // TODO: If we're adding envp/argv we need to make this conditional.
    // ! You must make sure the final RSP is 16-byte aligned ! (uncomment the line below if needed)
    if (3 + argv.len()) & 1 != 0 {
        stack.push_u64(0);
    }

    stack.push_pair(0, 0);
    stack.push_pair(15, at_platform);
    stack.push_pair(31, at_execfn);
    stack.push_pair(25, at_random);
    stack.push_pair(23, 0);
    stack.push_pair(14, 1000);
    stack.push_pair(13, 1000);
    stack.push_pair(12, 1000);
    stack.push_pair(11, 1000);
    stack.push_pair(9, entry_point);
    stack.push_pair(8, 0);
    stack.push_pair(7, loader.vbase);
    stack.push_pair(5, 9);
    stack.push_pair(4, 56);
    if let Some(phdr) = phdr {
        println!("Setting phdr = 0x{phdr:X}");
        stack.push_pair(3, phdr);
    }
    stack.push_pair(17, 100);
    stack.push_pair(6, 4096);
    // TODO: Remove these two pointers because we don't actually set them up properly?
    // stack.push_pair(16, 0xbbfebfbff);
    // stack.push_pair(33, 0xb7fff6c86b000); // TODO: Add a sysinfo ehdr

    stack.push_u64(0); // envp[0] = (nil)
    stack.push_u64(0); // argv[N] = (nil)

    for &argv in argv.iter().rev() {
        stack.push_u64(argv);
    }

    stack.push_u64(argv.len() as u64); // argc

    println!("Start of arguments: 0x{:X}", stack.rsp);

    CpuState::<A>::set_gpreg(state.cpu_mut(), GpReg::Rsp, stack.rsp);

    if let Some(interp) = args.interpreter_override.as_deref().or(binary.interpreter()) {
        loader.vbase = args
            .interp_vbase
            .map(|s| u64::from_str_radix(&s, 16).unwrap())
            .unwrap_or(0x7ffff7fc3000);

        println!("Loading interpreter from {interp:?}...");
        let binary_blob = fs::read(interp).unwrap();
        xmas_elf::ElfFile::new(&binary_blob).unwrap();
        let loader_binary = ElfBinary::new(&binary_blob).unwrap();
        loader_binary.load(&mut loader).unwrap();

        CpuState::<A>::set_gpreg(state.cpu_mut(), GpReg::Rip, loader_binary.entry_point() + loader.vbase);
    } else {
        CpuState::<A>::set_gpreg(state.cpu_mut(), GpReg::Rip, binary.entry_point() + loader.vbase);
    }

    let memory = loader.memories;
    with_oracle(|mut oracle| {
        let mut emu = Emulator::new(
            memory,
            state.cpu().clone(),
            args.cache,
            ElfBackend {
                oracle: &mut oracle,
                trace_execution: args.trace_execution,
                trace_delay: args.trace_execution_delay.unwrap_or(0),
                trace_syscalls: args.trace_syscalls,
                trace_rip: args.trace_rip,
                cross_check: args.cross_check,
                instruction_count: 0,
                expected_output_state: None,
                openat_remap: args
                    .openat_remap
                    .iter()
                    .map(|s| {
                        let pos = s.find('=').expect("usage: --openat-remap /original/path=/remapped/path");
                        (s[..pos].to_string(), CString::new(&s[pos + 1..]).unwrap())
                    })
                    .collect(),
            },
        )
        .unwrap();

        for path in args.semantics.iter() {
            println!("Reading existing semantics from {path:?}");
            let encodings: Vec<Encoding<_, SynthesizedComputation>> =
                serde_json::from_reader(BufReader::new(File::open(path).unwrap())).unwrap();

            println!("Building filter map...");
            for encoding in encodings {
                if encoding.all_outputs_have_computations() {
                    emu.add_encoding(encoding);
                }
            }
        }

        println!("Starting emulation...");

        emu.run();
    })
}
