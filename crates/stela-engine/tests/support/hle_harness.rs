//! The HLE differential harness: guest stand-ins for the functions HLE
//! replaces, each a self-contained A64 leaf; random and edge cases for them;
//! one run of a case on the native test host; a Rust model of each function
//! written from its C semantics; and the comparison of two runs of a case.
//!
//! A run uses this thread's code and data mappings (16 KiB each, between
//! inaccessible guards), so a case's pointers are offsets from the data
//! mapping, which [`data_base`] resolves with wrapping arithmetic: any
//! address is a case's pointer.
#![allow(dead_code, reason = "each HLE test uses part of the harness")]
#[path = "a64.rs"]
pub mod a64;
#[path = "store_host.rs"]
pub mod store_host;

use a64::*;
use anyhow::{Result, ensure};
use std::sync::Arc;
use stela_compiler::{GuestState, TargetCpu};
use stela_engine::{
    hle::{Config, Id, Signature, Statistics},
    machine::{Machine, NoDevices, Stop, exception::Pstate, system::Register},
};
use store_host::{Mapping, NativeHost, machine};

pub const PAGE: usize = 4096;
/// The bytes of the data mapping (and of the code mapping).
pub const BYTES: usize = 4 * PAGE;
/// The size bound generated cases are drawn for: a call of it fits the data
/// mapping with room to place it.
pub const CASE_MAX_BYTES: u32 = 4096;
/// The blocks one run may take: a byte loop over the whole mapping, twice.
const RUN_BLOCKS: u64 = 200_000;

thread_local! {
    static MAPPINGS: (Mapping, Mapping) = (
        Mapping::new().expect("map the code"),
        Mapping::new().expect("map the data"),
    );
}

fn with_mappings<R>(f: impl FnOnce(&Mapping, &Mapping) -> R) -> R {
    MAPPINGS.with(|(code, data)| f(code, data))
}

/// The guest address of this thread's code mapping, where a stand-in's
/// words start.
pub fn code_base() -> u64 {
    with_mappings(|code, _| code.0)
}

/// The guest address of this thread's data mapping, which a case's pointer
/// arguments are offsets from.
pub fn data_base() -> u64 {
    with_mappings(|_, data| data.0)
}

/// A guest function a native routine replaces: its words from the start of
/// the code page, the word it starts at, its exit `ret` (bytes from its
/// start), whether X0 holds a result, and the word of the `blr x16` that
/// calls it when a call enters it through one, on a guarded page.
#[derive(Debug, Clone)]
pub struct StandIn {
    pub id: Id,
    pub words: Vec<u32>,
    pub entry: usize,
    pub exit: u16,
    pub returns: bool,
    pub caller: Option<usize>,
    /// Calls start at the page's first word, a driver program ahead of the
    /// function that calls it (or runs into it) and ends with a branch to
    /// [`Self::end`].
    pub driven: bool,
}

impl StandIn {
    /// The function's own bytes, from its entry (its caller's `blr` is not
    /// one of them).
    pub fn function(&self) -> Vec<u8> {
        self.words[self.entry..self.caller.unwrap_or(self.words.len())]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    /// The same function `words` words into its code page, after NOPs.
    pub fn at(&self, words: usize) -> StandIn {
        let mut placed = vec![NOP; words];
        placed.extend_from_slice(&self.words[self.entry..]);
        StandIn {
            words: placed,
            entry: words,
            caller: self.caller.map(|caller| caller - self.entry + words),
            ..self.clone()
        }
    }

    /// The same function called by a `blr x16` after its last word, with
    /// its code page guarded (FEAT_BTI): the call enters with BTYPE 0b10,
    /// which only a first word such as `bti c` admits.
    pub fn through_blr(&self) -> StandIn {
        assert!(self.caller.is_none(), "one caller");
        let mut called = self.clone();
        called.caller = Some(called.words.len());
        called.words.push(BLR_X16);
        called
    }

    /// Its entry's guest address.
    pub fn pc(&self) -> u64 {
        code_base() + 4 * self.entry as u64
    }

    /// Where a call of it starts: its driver, its caller's `blr`, or its
    /// entry.
    pub fn start(&self) -> u64 {
        match self.driven {
            true => code_base(),
            false => code_base() + 4 * self.caller.unwrap_or(self.entry) as u64,
        }
    }

    /// The function after `driver`'s words, which calls start at: the
    /// driver's last word must branch to [`Self::end`].
    pub fn driven_by(&self, driver: &[u32]) -> StandIn {
        let mut driven = self.at(driver.len());
        driven.words[..driver.len()].copy_from_slice(driver);
        driven.driven = true;
        driven
    }

    /// The address its caller returns to: the word after its last, where
    /// the test host stops ([`store_host::machine`]).
    pub fn end(&self) -> u64 {
        code_base() + 4 * self.words.len() as u64
    }
}

/// The stand-in for `id`: a byte-at-a-time leaf with the routine's C
/// semantics, ending in a `ret`, NOPs before that pad it to the 8 words a
/// signature needs at least. `Bail` stands for memmove's.
pub fn stand_in(id: Id) -> StandIn {
    let (words, exit, returns) = match id {
        Id::Memmove | Id::Bail => (
            vec![
                cbz(2, 16),         // cbz x2, ret
                mov(3, 0),          // mov x3, x0
                sub(4, 0, 1),       // sub x4, x0, x1
                cmp(4, 2),          // cmp x4, x2
                b_cond(LO, 6),      // b.lo back: dst inside [src, src+n)
                ldrb_post(5, 1, 1), // forward: ldrb w5,[x1],#1
                strb_post(5, 3, 1), // strb w5,[x3],#1
                subs_imm(2, 2, 1),  // subs x2,x2,#1
                b_cond(NE, -3),     // b.ne forward
                b(7),               // b ret
                add(3, 0, 2),       // back: add x3,x0,x2
                add(1, 1, 2),       // add x1,x1,x2
                ldrb_pre(5, 1, -1), // backward: ldrb w5,[x1,#-1]!
                strb_pre(5, 3, -1), // strb w5,[x3,#-1]!
                subs_imm(2, 2, 1),  // subs x2,x2,#1
                b_cond(NE, -3),     // b.ne backward
                RET,                // ret: ret
            ],
            64,
            true,
        ),
        Id::Bzero => (
            vec![
                cbz(1, 7),           // cbz x1, ret
                mov(3, 0),           // mov x3, x0
                strb_post(ZR, 3, 1), // loop: strb wzr,[x3],#1
                subs_imm(1, 1, 1),   // subs x1,x1,#1
                b_cond(NE, -2),      // b.ne loop
                NOP,
                NOP,
                RET, // ret: ret
            ],
            28,
            false,
        ),
        Id::Memset => (
            vec![
                BTI_C,              // bti c
                cbz(2, 6),          // cbz x2, ret
                mov(3, 0),          // mov x3, x0
                strb_post(1, 3, 1), // loop: strb w1,[x3],#1
                subs_imm(2, 2, 1),  // subs x2,x2,#1
                b_cond(NE, -2),     // b.ne loop
                NOP,
                RET, // ret: ret
            ],
            28,
            true,
        ),
        Id::Memcmp => (
            vec![
                cbz(2, 7),          // cbz x2, zero
                ldrb_post(3, 0, 1), // loop: ldrb w3,[x0],#1
                ldrb_post(4, 1, 1), // ldrb w4,[x1],#1
                subs_w(3, 3, 4),    // subs w3,w3,w4
                b_cond(NE, 5),      // b.ne diff
                subs_imm(2, 2, 1),  // subs x2,x2,#1
                b_cond(NE, -5),     // b.ne loop
                movz_w(0, 0),       // zero: mov w0,#0
                RET,                // ret (the exit)
                mov_w(0, 3),        // diff: mov w0,w3
                RET,                // ret
            ],
            32,
            true,
        ),
        Id::Strlen => (
            vec![
                ldrb(2, 0),        // ldrb w2,[x0]
                mov(1, 0),         // mov x1,x0
                cbz_w(2, 3),       // cbz w2, done
                ldrb_pre(2, 1, 1), // loop: ldrb w2,[x1,#1]!
                cbnz_w(2, -1),     // cbnz w2, loop
                sub(0, 1, 0),      // done: sub x0,x1,x0
                NOP,
                RET, // ret
            ],
            28,
            true,
        ),
        Id::Touch => (
            vec![
                ldrb(8, 1),   // ldrb w8,[x1]
                ldrb(9, 0),   // ldrb w9,[x0]
                add(0, 8, 9), // add x0,x8,x9
                NOP,
                NOP,
                NOP,
                NOP,
                RET, // ret
            ],
            28,
            true,
        ),
    };
    StandIn {
        id,
        words,
        entry: 0,
        exit,
        returns,
        caller: None,
        driven: false,
    }
}

/// The routines' stand-ins, each once (`Bail` is memmove's).
pub const STAND_INS: [Id; 6] = [
    Id::Memmove,
    Id::Bzero,
    Id::Memset,
    Id::Memcmp,
    Id::Strlen,
    Id::Touch,
];

/// The argument registers of `id` that hold pointers, which a case gives as
/// offsets from [`data_base`].
pub fn pointers(id: Id) -> &'static [usize] {
    match id {
        Id::Memmove | Id::Bail | Id::Memcmp | Id::Touch => &[0, 1],
        Id::Bzero | Id::Memset | Id::Strlen => &[0],
    }
}

/// A one-entry table of `stand_in`'s function under `id`.
pub fn table(stand_in: &StandIn, id: Id) -> Arc<[Signature]> {
    let signature = Signature::of(id, &stand_in.function(), stand_in.exit)
        .expect("a stand-in is an eligible leaf");
    Arc::from([signature])
}

/// One call: X0-X2 (pointers as offsets from [`data_base`]), the data
/// mapping's contents, the page of it that is unreadable or read-only, and
/// the size bound the case was drawn for.
#[derive(Debug, Clone)]
pub struct Case {
    pub x: [u64; 3],
    pub contents: Vec<u8>,
    pub unreadable: Option<usize>,
    pub read_only: Option<usize>,
    pub max_bytes: u32,
}

/// `STELA_HLE_CASES`, or `default`.
pub fn case_count(default: usize) -> usize {
    std::env::var("STELA_HLE_CASES")
        .ok()
        .and_then(|count| count.parse().ok())
        .unwrap_or(default)
}

/// Xorshift, as the engine's other native suites draw cases.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// `count` cases for `id` from `seed`, sizes up to [`CASE_MAX_BYTES`].
pub fn cases(id: Id, seed: u64, count: usize) -> Vec<Case> {
    case_stream(id, seed, count).collect()
}

/// [`cases`], made one at a time: a case holds the whole data mapping, so
/// the acceptance run's million would not fit in memory at once.
pub fn case_stream(id: Id, seed: u64, count: usize) -> impl Iterator<Item = Case> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    (0..count).map(move |_| case(id, &mut rng))
}

fn case(id: Id, rng: &mut Rng) -> Case {
    let max_bytes = CASE_MAX_BYTES;
    // Half the sizes at most 256, the rest up to the bound and past it.
    let n = if rng.below(2) == 0 {
        rng.below(257)
    } else {
        rng.below(u64::from(max_bytes) + 65)
    };
    let mut contents: Vec<u8> = (0..BYTES).map(|_| rng.next() as u8).collect();
    let (x, buffers) = match id {
        Id::Memmove | Id::Bail => {
            let (dst, src) = overlapping(rng, n);
            ([dst, src, n], vec![(dst, n), (src, n)])
        }
        Id::Bzero => {
            let at = place(rng, n);
            ([at, n, rng.next()], vec![(at, n)])
        }
        Id::Memset => {
            let at = place(rng, n);
            ([at, rng.next(), n], vec![(at, n)])
        }
        Id::Memcmp => {
            let (a, b) = (place(rng, n), place(rng, n));
            compared(rng, &mut contents, a, b, n);
            ([a, b, n], vec![(a, n), (b, n)])
        }
        Id::Strlen => {
            let (start, scanned) = string(rng, &mut contents);
            ([start, rng.next(), rng.next()], vec![(start, scanned)])
        }
        Id::Touch => {
            let (a, b) = (rng.below(BYTES as u64), rng.below(BYTES as u64));
            ([a, b, rng.next()], vec![(a, 1), (b, 1)])
        }
    };
    let (unreadable, read_only) = faulting(rng, &buffers);
    Case {
        x,
        contents,
        unreadable,
        read_only,
        max_bytes,
    }
}

/// An offset for a buffer of `n` bytes, aligned 0 to 63 past a 64-byte
/// boundary, which leaves it inside the mapping unless that alignment
/// takes it past the end.
fn place(rng: &mut Rng, n: u64) -> u64 {
    let room = (BYTES as u64).saturating_sub(n);
    rng.below(room / 64 + 1) * 64 + rng.below(64)
}

/// memmove's destination and source for one of its overlap classes:
/// disjoint, forward (the destination below), backward (above), exact or
/// adjacent.
fn overlapping(rng: &mut Rng, n: u64) -> (u64, u64) {
    let class = rng.below(5);
    if class == 0 {
        return (place(rng, n), place(rng, n));
    }
    let apart = match class {
        1 | 2 => 1 + rng.below(n.max(1)),
        3 => 0,
        _ => n,
    };
    let low = place(rng, n + apart);
    match class {
        1 => (low, low + apart),
        2 => (low + apart, low),
        3 => (low, low),
        _ if rng.below(2) == 0 => (low, low + apart),
        _ => (low + apart, low),
    }
}

/// memcmp's second buffer: in most cases a copy of the first, with one
/// byte changed in three of four, so a compare runs to a chosen byte.
fn compared(rng: &mut Rng, contents: &mut [u8], a: u64, b: u64, n: u64) {
    let (a, b, n) = (a as usize, b as usize, n as usize);
    if rng.below(8) == 0 || a + n > BYTES || b + n > BYTES {
        return;
    }
    contents.copy_within(a..a + n, b);
    if n != 0 && rng.below(4) != 0 {
        let at = b + rng.below(n as u64) as usize;
        contents[at] = contents[at].wrapping_add(1 + rng.below(255) as u8);
    }
}

/// strlen's string: its start, and the bytes a scan reads (to its NUL, or
/// to the mapping's end). Its NUL lies at random, just before, at or after
/// a page end, or nowhere, when the scan runs into the guard.
fn string(rng: &mut Rng, contents: &mut [u8]) -> (u64, u64) {
    let start = rng.below(BYTES as u64 - 1) as usize;
    for byte in &mut contents[start..] {
        *byte |= 1;
    }
    let room = (BYTES - start) as u64;
    let nul = match rng.below(16) {
        0 => None,
        1..=5 => Some(start + rng.below(room.min(300)) as usize),
        6..=10 => Some(start + rng.below(room) as usize),
        _ => {
            let page = PAGE * (1 + rng.below(3) as usize);
            let at = page + rng.below(3) as usize - 1;
            Some(if at >= start { at } else { start })
        }
    };
    match nul {
        Some(nul) => {
            contents[nul] = 0;
            (start as u64, (nul - start + 1) as u64)
        }
        None => (start as u64, room),
    }
}

/// The page made unreadable (an eighth of the cases) or read-only (a
/// sixteenth): one a buffer starts, ends or crosses into, one at its middle,
/// or any.
fn faulting(rng: &mut Rng, buffers: &[(u64, u64)]) -> (Option<usize>, Option<usize>) {
    let kind = rng.below(16);
    if kind > 2 {
        return (None, None);
    }
    let (at, n) = buffers[rng.below(buffers.len() as u64) as usize];
    let page = match rng.below(5) {
        0 => rng.below(4),
        1 => at / PAGE as u64,
        2 => (at + n / 2) / PAGE as u64,
        3 => (at + n.saturating_sub(1)) / PAGE as u64,
        _ => at / PAGE as u64 + 1,
    };
    let page = (page < 4).then_some(page as usize);
    if kind < 2 { (page, None) } else { (None, page) }
}

/// The stop and PC of a call that aborted: the test kernel's lower-EL
/// synchronous vector, by its offset (`store_host::machine` maps a kernel
/// for each machine, so its address names the machine, not the call).
pub const VECTOR: u64 = 0x400;

/// What a run ends in: its stop, PC, registers and PSTATE (BTYPE among
/// it), the instructions it retired, the data mapping and, for an abort,
/// ESR, FAR, ELR and SPSR.
#[derive(Debug, PartialEq)]
pub struct Outcome {
    pub stop: Stop,
    pub pc: u64,
    pub state: GuestState,
    pub pstate: Pstate,
    pub retired: u64,
    pub memory: Vec<u8>,
    pub abort: Option<(u64, u64, u64, u64)>,
}

/// The exception class of an abort's ESR.
pub fn exception_class(esr: u64) -> u64 {
    esr >> 26 & 0x3f
}

/// ESR's class of a Branch Target exception.
pub const BRANCH_TARGET: u64 = 0x0d;

/// The syndrome registers an abort writes, which each call clears first
/// so it ends as on a fresh machine: a Branch Target exception, for one,
/// leaves FAR as it was.
const ABORT_REGISTERS: [Register; 4] = [
    Register::ESR_EL1,
    Register::FAR_EL1,
    Register::ELR_EL1,
    Register::SPSR_EL1,
];

/// A machine with a stand-in in its code page, for one or more calls. A
/// suite runs its cases on one: a debug build takes about 0.1 s to make a
/// machine and well under a millisecond to run a call on a warm one.
pub struct Session {
    stand_in: StandIn,
    machine: Machine<NativeHost, NoDevices>,
}

impl Session {
    /// A machine for `stand_in`, with HLE configured as `hle` says, or
    /// never configured (`None`).
    pub fn new(stand_in: &StandIn, hle: Option<Config>) -> Result<Self> {
        Self::with_target(stand_in, hle, TargetCpu::detect())
    }

    /// [`Self::new`], compiling for `target` (one of [`targets`]), whose
    /// vectors a native's fast path uses.
    pub fn with_target(stand_in: &StandIn, hle: Option<Config>, target: TargetCpu) -> Result<Self> {
        let machine = with_mappings(|code, data| {
            // The page holds this function alone.
            ensure!(code.write(code.0, &[0; BYTES]), "clear the code");
            let mut machine = machine(code, data, &stand_in.words, target)?;
            machine.set_regions(false);
            if stand_in.caller.is_some() {
                machine.host.guard(code.0, BYTES);
            }
            if let Some(config) = hle {
                machine.set_hle(config);
            }
            Ok(machine)
        })?;
        Ok(Self {
            stand_in: stand_in.clone(),
            machine,
        })
    }

    pub fn machine(&mut self) -> &mut Machine<NativeHost, NoDevices> {
        &mut self.machine
    }

    /// What the machine's HLE did in all its calls so far.
    pub fn hle(&self) -> Statistics {
        self.machine.hle_statistics()
    }

    /// Call the stand-in once with `case`, from EL0. A call the last one
    /// left at the test kernel's vector (an abort) returns from there first,
    /// as the vector's ERET would.
    pub fn run(&mut self, case: &Case) -> Result<Outcome> {
        ensure!(
            case.contents.len() == BYTES,
            "a case holds the data mapping"
        );
        if self.machine.cpu.pstate.el != 0 {
            self.machine
                .resume_exception()
                .map_err(|status| anyhow::anyhow!("return from an abort: {status:?}"))?;
        }
        ensure!(self.machine.cpu.pstate.el == 0, "a call starts at EL0");
        // A new call: the ERET took the aborted call's BTYPE back from SPSR.
        self.machine.cpu.pstate.btype = 0;
        for register in ABORT_REGISTERS {
            self.machine.cpu.registers.set_raw(register, 0, 0);
        }
        let state = initial(&self.stand_in, case);
        with_mappings(|_, data| -> Result<Outcome> {
            ensure!(data.write(data.0, &case.contents), "write data");
            if let Some(page) = case.unreadable {
                data.protect(page * PAGE, PAGE, false)?;
            }
            if let Some(page) = case.read_only {
                read_only(data, page)?;
            }
            let machine = &mut self.machine;
            machine.cpu.state = state;
            machine.cpu.pc = self.stand_in.start();
            let retired = machine.cpu.retired;
            let stop = machine.run(machine.statistics.blocks + RUN_BLOCKS);
            for page in [case.unreadable, case.read_only].into_iter().flatten() {
                data.protect(page * PAGE, PAGE, true)?;
            }
            let aborted = stop == Stop::Breakpoint(machine.host.lower_synchronous());
            let abort = aborted.then(|| {
                let [esr, far, elr, spsr] =
                    ABORT_REGISTERS.map(|register| machine.cpu.registers.get(register, 0));
                (esr, far, elr, spsr)
            });
            // Each machine maps its test kernel anew: an abort's stop names
            // the vector it took, not where this machine mapped it.
            let (stop, pc) = match aborted {
                true => (Stop::Breakpoint(VECTOR), VECTOR),
                false => (stop, machine.cpu.pc),
            };
            Ok(Outcome {
                stop,
                pc,
                state: machine.cpu.state.clone(),
                pstate: machine.cpu.pstate,
                retired: machine.cpu.retired - retired,
                memory: data.read(data.0, BYTES).expect("readable data"),
                abort,
            })
        })
    }
}

/// Make data page `page` readable but not writable: an access to it from
/// native code faults as the test host's permission fault.
fn read_only(data: &Mapping, page: usize) -> Result<()> {
    // SAFETY: a page of this thread's data mapping, which no Rust reference
    // covers; the run restores its rights before the mapping is read.
    let protected = unsafe {
        libc::mprotect(
            (data.0 + (page * PAGE) as u64) as *mut _,
            PAGE,
            libc::PROT_READ,
        )
    };
    ensure!(
        protected == 0,
        "protect test RAM: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

/// The registers a call starts with: the case's arguments, the return to
/// the stand-in's end (and X16 at its entry, for a call through `blr x16`,
/// which sets X30 itself), and the rest drawn from the arguments so both
/// runs of a case start alike.
fn initial(stand_in: &StandIn, case: &Case) -> GuestState {
    let mut rng = Rng(
        (case.x[0] ^ case.x[1].rotate_left(21) ^ case.x[2].rotate_left(42))
            .wrapping_mul(0x2545_f491_4f6c_dd1d)
            | 1,
    );
    let mut state = GuestState {
        x: std::array::from_fn(|_| rng.next()),
        sp: rng.next() & !15,
        v: std::array::from_fn(|_| [rng.next(), rng.next()]),
        nzcv: (rng.next() as u32) & 0xf000_0000,
        ..GuestState::default()
    };
    for (register, &value) in case.x.iter().enumerate() {
        state.x[register] = if pointers(stand_in.id).contains(&register) {
            data_base().wrapping_add(value)
        } else {
            value
        };
    }
    state.x[30] = stand_in.end();
    if stand_in.caller.is_some() {
        state.x[16] = stand_in.pc();
    }
    state
}

/// One call of `stand_in` with `case`, on a machine of its own (see
/// [`Session`] for many), with HLE as `hle` configures it, bounded at the
/// case's size bound, and what its HLE did.
pub fn run(stand_in: &StandIn, case: &Case, hle: Option<Config>) -> Result<(Outcome, Statistics)> {
    let hle = hle.map(|config| config.with_max_bytes(case.max_bytes));
    let mut session = Session::new(stand_in, hle)?;
    let outcome = session.run(case)?;
    Ok((outcome, session.hle()))
}

/// The byte at data offset `at` is in the mapping and readable.
fn readable(case: &Case, at: u64) -> bool {
    at < BYTES as u64 && case.unreadable != Some(at as usize / PAGE)
}

/// ... and writable.
fn writable(case: &Case, at: u64) -> bool {
    readable(case, at) && case.read_only != Some(at as usize / PAGE)
}

fn all(case: &Case, at: u64, n: u64, byte: fn(&Case, u64) -> bool) -> bool {
    (0..n).all(|index| at.checked_add(index).is_some_and(|at| byte(case, at)))
}

/// The C semantics of `id` on `case`: X0 (when it returns a value) and the
/// data mapping after the call, or `None` when the call must fault. Copies
/// and fills are `ptr::copy` and `write_bytes`; memcmp, strlen and touch
/// read byte by byte and stop where their result is known.
pub fn reference(id: Id, case: &Case) -> Option<(Option<u64>, Vec<u8>)> {
    let [x0, x1, x2] = case.x;
    let mut memory = case.contents.clone();
    let result = match id {
        Id::Memmove | Id::Bail => {
            if !all(case, x1, x2, readable) || !all(case, x0, x2, writable) {
                return None;
            }
            // No byte moves, wherever the pointers point.
            if x2 != 0 {
                let (dst, src, n) = (x0 as usize, x1 as usize, x2 as usize);
                memory.copy_within(src..src + n, dst);
            }
            Some(data_base().wrapping_add(x0))
        }
        Id::Bzero | Id::Memset => {
            let (value, n) = match id {
                Id::Bzero => (0, x1),
                _ => (x1 as u8, x2),
            };
            if !all(case, x0, n, writable) {
                return None;
            }
            if n != 0 {
                memory[x0 as usize..(x0 + n) as usize].fill(value);
            }
            (id == Id::Memset).then(|| data_base().wrapping_add(x0))
        }
        Id::Memcmp => {
            let mut difference = 0;
            for index in 0..x2 {
                let (a, b) = (x0.wrapping_add(index), x1.wrapping_add(index));
                if !readable(case, a) || !readable(case, b) {
                    return None;
                }
                let (a, b) = (memory[a as usize], memory[b as usize]);
                if a != b {
                    difference = u64::from(u32::from(a).wrapping_sub(u32::from(b)));
                    break;
                }
            }
            Some(difference)
        }
        Id::Strlen => {
            let mut length = 0;
            loop {
                let at = x0.wrapping_add(length);
                if !readable(case, at) {
                    return None;
                }
                if memory[at as usize] == 0 {
                    break Some(length);
                }
                length += 1;
            }
        }
        Id::Touch => {
            if !readable(case, x1) || !readable(case, x0) {
                return None;
            }
            Some(u64::from(memory[x1 as usize]) + u64::from(memory[x0 as usize]))
        }
    };
    Some((result, memory))
}

/// Whether `on` ends as `off` does, for a call of `stand_in` with `case`.
/// Unless both returned to the caller, they must be equal in full: the
/// original takes any fault in both. When both returned, they must agree on
/// what the ABI keeps: the PC, all memory, X19-X29, SP, X30, the low halves
/// of V8-V15, FPCR and FPSR, X0 where it is a result, and PSTATE; and `on`
/// must leave memory and X0 as the reference model does.
pub fn agree(stand_in: &StandIn, case: &Case, off: &Outcome, on: &Outcome) -> Result<(), String> {
    let end = Stop::Breakpoint(stand_in.end());
    if off.stop != end || on.stop != end {
        return match off == on {
            true => Ok(()),
            false => Err(format!(
                "outcomes differ: off {:?} pc {:#x} abort {:x?}, on {:?} pc {:#x} abort {:x?}",
                off.stop, off.pc, off.abort, on.stop, on.pc, on.abort
            )),
        };
    }
    let (a, b) = (&off.state, &on.state);
    let kept = [
        ("pc", off.pc == on.pc),
        ("memory", off.memory == on.memory),
        ("x19-x29", a.x[19..=29] == b.x[19..=29]),
        ("sp", a.sp == b.sp),
        ("x30", a.x[30] == b.x[30]),
        (
            "v8-v15",
            (8..16).all(|register| a.v[register][0] == b.v[register][0]),
        ),
        ("fpcr", a.fpcr == b.fpcr),
        ("fpsr", a.fpsr == b.fpsr),
        ("x0", !stand_in.returns || a.x[0] == b.x[0]),
        ("pstate", off.pstate == on.pstate),
    ];
    if let Some((name, _)) = kept.iter().find(|(_, equal)| !equal) {
        return Err(format!("{name} differs"));
    }
    match reference(stand_in.id, case) {
        // Real platform memmove/memcpy implementations (including Apple's
        // libsystem_platform) short-circuit `dst == src` without touching
        // memory, and HLE's fault-bypass preserves that exact behavior.
        None if stand_in.id == Id::Memmove
            && case.x[0] == case.x[1]
            && on.memory == case.contents
            && on.state.x[0] == data_base().wrapping_add(case.x[0]) =>
        {
            Ok(())
        }
        None => Err("returned where the reference model faults".into()),
        Some((_, memory)) if memory != on.memory => {
            Err("memory differs from the reference model".into())
        }
        Some((x0, _)) if stand_in.returns && x0 != Some(b.x[0]) => {
            Err("x0 differs from the reference model".into())
        }
        Some(_) => Ok(()),
    }
}

/// The vector sets this host runs a fast path with: SSE2 always, AVX2 and
/// AVX-512F where it has them, each a target a session compiles for.
pub fn targets() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    let mut targets = vec![TargetCpu::Baseline];
    if host.supports(TargetCpu::Avx2) {
        targets.push(TargetCpu::Avx2);
    }
    if host.supports(TargetCpu::Avx512f) {
        targets.push(host);
    }
    targets
}

/// Whether a run is the acceptance run (`STELA_HLE_CASES` of 100000 or
/// more), which also runs the exhaustive suites in full.
pub fn exhaustive() -> bool {
    case_count(0) >= 100_000
}

/// A case of `id` with arguments `x` (pointers as data offsets) over random
/// `contents` from `seed`, a page unreadable or read-only, bounded at
/// [`CASE_MAX_BYTES`].
pub fn case_of(
    x: [u64; 3],
    seed: u64,
    unreadable: Option<usize>,
    read_only: Option<usize>,
) -> Case {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    Case {
        x,
        contents: (0..BYTES).map(|_| rng.next() as u8).collect(),
        unreadable,
        read_only,
        max_bytes: CASE_MAX_BYTES,
    }
}

/// What [`Differential::check`] saw of one case: the original's run, the
/// native's on each target, and whether every one of those ran the fast
/// path to its exit (two instructions retired, the composite and the
/// `ret`, and no bypass).
pub struct Checked {
    pub off: Outcome,
    pub on: Vec<Outcome>,
    pub native: bool,
    pub bypassed: bool,
}

/// One routine's differential: its stand-in run with HLE off on one
/// machine, and with its native on a machine per target ([`targets`]),
/// all reused across cases as a hot function's composite is.
pub struct Differential {
    pub stand_in: StandIn,
    off: Session,
    on: Vec<(TargetCpu, Session)>,
}

impl Differential {
    /// `id`'s stand-in under its own native, bounded at `max_bytes`.
    pub fn new(id: Id, max_bytes: u32) -> Result<Self> {
        Self::of(stand_in(id), id, max_bytes)
    }

    /// `stand_in`'s function under `routine`.
    pub fn of(stand_in: StandIn, routine: Id, max_bytes: u32) -> Result<Self> {
        let config =
            Config::with_table(table(&stand_in, routine), &[routine]).with_max_bytes(max_bytes);
        let on = targets()
            .into_iter()
            .map(|target| {
                Ok((
                    target,
                    Session::with_target(&stand_in, Some(config.clone()), target)?,
                ))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            off: Session::new(&stand_in, None)?,
            on,
            stand_in,
        })
    }

    /// Every machine of the differential, the original's first: for a
    /// suite to set the System registers its function needs.
    pub fn machines(&mut self) -> impl Iterator<Item = &mut Machine<NativeHost, NoDevices>> {
        std::iter::once(&mut self.off)
            .chain(self.on.iter_mut().map(|(_, session)| session))
            .map(Session::machine)
    }

    /// The HLE counts of each target's machine.
    pub fn statistics(&self) -> Vec<(TargetCpu, Statistics)> {
        self.on
            .iter()
            .map(|(target, session)| (*target, session.hle()))
            .collect()
    }

    /// Run `case` off and on every target: each must [`agree`] with the
    /// original, an error naming the target and the case otherwise.
    pub fn check(&mut self, case: &Case) -> Result<Checked> {
        self.check_with(case, false)
    }

    /// [`Self::check`] of a call the native must bail on: each target's
    /// run must equal the original's in full, as the original runs in
    /// both, whatever the reference model says of it.
    pub fn check_bailed(&mut self, case: &Case) -> Result<Checked> {
        self.check_with(case, true)
    }

    fn check_with(&mut self, case: &Case, bailed: bool) -> Result<Checked> {
        let off = self.off.run(case)?;
        let mut on = Vec::new();
        let (mut native, mut bypassed) = (true, false);
        for (target, session) in &mut self.on {
            let before = session.hle().bypassed;
            let outcome = session.run(case)?;
            let agreed = match bailed {
                true if outcome == off => Ok(()),
                true => Err("differs from the original in full".into()),
                false => agree(&self.stand_in, case, &off, &outcome),
            };
            if let Err(why) = agreed {
                anyhow::bail!(
                    "{:?} on {}: {why}: x {:x?} unreadable {:?} read-only {:?}; off {:?} retired {} abort {:x?}, on {:?} retired {} abort {:x?}",
                    self.stand_in.id,
                    target.id(),
                    case.x,
                    case.unreadable,
                    case.read_only,
                    off.stop,
                    off.retired,
                    off.abort,
                    outcome.stop,
                    outcome.retired,
                    outcome.abort,
                );
            }
            let faulted = session.hle().bypassed != before;
            bypassed |= faulted;
            native &= !faulted
                && outcome.retired == 2
                && outcome.stop == Stop::Breakpoint(self.stand_in.end());
            on.push(outcome);
        }
        Ok(Checked {
            off,
            on,
            native,
            bypassed,
        })
    }
}
