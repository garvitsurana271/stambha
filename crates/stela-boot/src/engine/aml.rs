//! The host firmware's AML, run by the pinned ACPICA
//! (`stela_drivers::platform::acpi`, whose `Services` table is the provider
//! contract) through the engine's own OSL services: its heap, the TSC, port I/O, PCI
//! configuration space and the loader root's mappings.
//!
//! The boot keeps its EC binding before namespace initialization. When the
//! captured SCI resources check, a native interrupt masks the owned line
//! and the BSP later dispatches ACPICA and its FIFO work under RestoreRoot.
//! Power-device notifications coalesce into refresh work on that same BSP.
//!
//! Every ACPICA call runs on the boot processor under the loader root
//! ([`super::storage::RestoreRoot`]), with interrupts off and the host drivers' lock held.
//! There RAM, ACPI tables and NVS included, is reached through the physmap,
//! write-back; any other address, device registers, through an identity
//! mapping the provider adds to the loader root uncached on first use. When
//! the native PCI source takes configuration custody, AML has scoped scalar
//! reads through that source, for its PCI_Config fields and for its
//! SystemMemory fields that land in an ECAM window, which ACPICA reaches
//! through [`read_memory`]. Its writes there are refused, except inside
//! [`HostAcpi::firmware`] calls that admit them before the PCI census,
//! while PCI ports are powered on (`super::pci_power`). Otherwise the
//! firmware provider uses PCI configuration mechanism #1 and the MCFG's
//! ECAM windows.
//!
//! The namespace loads before the PCI census, so ports can be powered on
//! before it, and its devices' `_INI` runs there too, with or without
//! hardware mode; hardware mode, with its SCI route, follows the census
//! ([`HostAcpi::activate`]), and only with `--acpi-hardware`
//! ([`stela_boot_core::acpi_hardware`]): the SCI's storm guard and the EC's
//! query budget and failure breaker are that module's.
pub(super) mod sci;
use super::{
    host,
    kernel_work::KernelWork,
    power::{in8, in16, in32, out8, out16, out32},
};
use crate::{
    layout, native_mmio, output,
    tables::{self, Frames, NX, PAGE, PRESENT, UNCACHED, WRITABLE},
};
use alloc::{boxed::Box, collections::VecDeque, string::String, vec::Vec};
use core::{
    alloc::Layout,
    arch::asm,
    cell::{Cell, RefCell},
    ffi::{c_char, c_void},
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use stela_boot_core::{
    acpi_hardware::{self as hardware_mode, Admit, EcGovernor, SciGovernor},
    ecam::memory as ecam_memory,
};
use stela_drivers::{
    bus::pci::{Address, EcamWindow},
    platform::acpi::{
        Bound, FULL_CAPABILITIES, Interrupt, Mode, PciId, SERVICES_ABI_BYTES, SERVICES_ABI_VERSION,
        Services, Session, Status, Value, Work,
    },
    usb::typec::ucsi::acpi::attachment as ucsi,
};
use stela_engine::machine::mmu::placement::Placement;

// ACPICA's statuses (`acexcep.h`).
const AE_OK: Status = 0;
const AE_ERROR: Status = 0x0001;
const AE_NOT_EXIST: Status = 0x0006;
const AE_SUPPORT: Status = 0x000f;
const AE_LIMIT: Status = 0x0010;
const AE_TIME: Status = 0x0011;
const AE_BAD_PARAMETER: Status = 0x1001;
/// `ACPI_WAIT_FOREVER`, a semaphore wait with no timeout.
const WAIT_FOREVER: u16 = 0xffff;
/// `ACPI_SIGNAL_FATAL`: AML's Fatal operator.
const SIGNAL_FATAL: u32 = 0;
/// RFLAGS.IF.
const INTERRUPTS: u64 = 1 << 9;
/// Connector changes one poll reads from a UCSI manager, bounding a port that
/// keeps changing; the rest stay pending for the next poll.
const UCSI_SERVICE_BUDGET: usize = 16;
const PCI_ADDRESS: u16 = 0xcf8;
const PCI_DATA: u16 = 0xcfc;
/// The header [`allocate`] keeps before each allocation: its layout's size.
const HEADER: usize = 16;
/// How long one call into the firmware's AML may run ([`bounded`]): far
/// past a whole table load and namespace initialization (about 100 ms on
/// the PCs logged so far) and ACPICA's 2 s Sleep, and well below the step
/// watchdog's 30 s, so AML that never finishes ends in its degraded answer
/// rather than a stop. Linux has no such bound; it has ACPICA's 30 s per
/// While loop, which nested methods and repeated loops add up past.
const AML_BOUND_MS: u32 = 10_000;

/// `call` into the firmware's AML under [`AML_BOUND_MS`], and whether it
/// finished within it. Past it, the methods running end with errors
/// ([`Bound`]), and one line names `what` did not finish, where AML was
/// then, and `then`, what follows.
fn bounded<T>(what: &str, then: &str, call: impl FnOnce() -> T) -> (T, bool) {
    // Each call has its own bound, so each starts the step watchdog's limit
    // again while the boot processor runs alone: many calls that each end
    // are no stuck step, whatever they add up to.
    super::step_watchdog::progress();
    let bound = Bound::begin(AML_BOUND_MS);
    IN_AML.store(true, Ordering::Relaxed);
    let value = call();
    IN_AML.store(false, Ordering::Relaxed);
    match bound.end() {
        Ok(()) => (value, true),
        Err(overrun) => {
            output::arguments(format_args!(
                "UNSUPPORTED ACPI {what} did not finish within {} s, {overrun}: {then}\n",
                AML_BOUND_MS / 1000
            ));
            (value, false)
        }
    }
}

/// A [`bounded`] call into the firmware's AML runs on the boot processor.
static IN_AML: AtomicBool = AtomicBool::new(false);

/// Where the firmware's AML runs on this processor, for a stop's reason
/// (the step watchdog's NMI): `None` outside a call into it.
pub(super) fn running_here() -> Option<stela_drivers::platform::acpi::Location> {
    if !IN_AML.load(Ordering::Relaxed) {
        return None;
    }
    // SAFETY: ACPICA runs only on the boot processor, inside `bounded`; the
    // caller is that processor's NMI handler, which stopped it where it runs.
    unsafe { stela_drivers::platform::acpi::running() }
}

/// What the provider reports once, as unsupported.
#[derive(Clone, Copy)]
enum Gap {
    /// A wait no other processor or interrupt could ever end.
    Wait = 1,
    /// Configuration space beyond mechanism #1 that no ECAM window decodes.
    Config = 2,
    /// An address beyond what the loader root can map by identity.
    Address = 4,
    /// Access that would bypass the native PCI configuration owner.
    PciCustody = 8,
    /// An AML SystemMemory read in ECAM the native PCI owner refused.
    EcamRead = 16,
    /// An AML SystemMemory write in ECAM, under native PCI custody.
    EcamWrite = 32,
    /// An AML configuration write admitted before the census that the
    /// native PCI owner refused.
    PowerWrite = 64,
}

struct Provider {
    /// The one BSP executor; Session callbacks never infer a task from IF.
    executor: &'static KernelWork,
    /// The loader root, which takes the identity mappings of device pages.
    root: u64,
    ecam: Vec<EcamWindow>,
    pci: Option<&'static native_mmio::Source>,
    tsc_hz: u64,
    /// `acpi_os_execute`'s work, run in order by [`drain_work`].
    work: RefCell<VecDeque<(Work, usize)>>,
    queued: AtomicBool,
    /// Quiesced: work is refused.
    closed: Cell<bool>,
    reported: Cell<u32>,
    prepared_sci: RefCell<Option<sci::Prepared>>,
    sci: RefCell<Option<sci::Armed>>,
    /// The SCI's storm guard, from its first dispatch.
    sci_governor: Cell<Option<SciGovernor>>,
    polling: Cell<bool>,
    needs_rearm: Cell<bool>,
    /// AML may write PCI configuration through the native owner while it
    /// powers ports on before the census ([`HostAcpi::firmware`]).
    config_writes: Cell<bool>,
    /// The FADT's `SMI_CMD` port, whose writes call the firmware's system
    /// management code, and the writes made to it.
    smi_command: Option<u16>,
    smi_writes: Cell<stela_boot_core::smi::CommandWrites>,
}

impl Provider {
    fn report(&self, gap: Gap, message: core::fmt::Arguments<'_>) {
        let bit = gap as u32;
        if self.reported.get() & bit == 0 {
            self.reported.set(self.reported.get() | bit);
            output::arguments(format_args!("UNSUPPORTED ACPI {message}\n"));
        }
    }

    /// `bytes` at `physical` under the loader root: through the physmap
    /// where it maps every page (RAM), else by identity, mapping the pages
    /// not yet mapped uncached. No ECAM page is lent under native custody:
    /// its scalar accesses go through [`Self::configuration_owner`].
    fn reach(&self, physical: u64, bytes: u64) -> Option<*mut u8> {
        let end = physical.checked_add(bytes.max(1))?;
        if self.configuration_owner(physical, bytes).is_some() {
            self.report(
                Gap::PciCustody,
                format_args!("native PCI configuration lends no mapping of ECAM at {physical:#x}"),
            );
            return None;
        }
        let pages = (physical & !(PAGE - 1)..end).step_by(PAGE as usize);
        if pages
            .clone()
            .all(|page| self.mapped(layout::physical(page)))
        {
            return Some(layout::physical(physical) as *mut u8);
        }
        let limit = match layout::placement() {
            Placement::FiveLevel => 1 << 52,
            Placement::FourLevel { .. } => 1 << 47,
        };
        if end > limit {
            self.report(
                Gap::Address,
                format_args!("firmware address {physical:#x} lies beyond the identity map"),
            );
            return None;
        }
        for page in pages {
            if !self.mapped(page) {
                let rights = PRESENT | WRITABLE | NX | UNCACHED;
                tables::map_page(&mut HeapFrames, self.root, page, page, rights).ok()?;
            }
        }
        Some(physical as *mut u8)
    }

    /// The native PCI owner, when `bytes` at `physical` touch an ECAM window
    /// under its custody.
    fn configuration_owner(
        &self,
        physical: u64,
        bytes: u64,
    ) -> Option<&'static native_mmio::Source> {
        self.pci
            .filter(|_| ecam_memory::touches(&self.ecam, physical, bytes))
    }

    /// AML's read of `bytes` at `physical` in an ECAM window, as the
    /// configuration reads of the functions it decodes to, which the native
    /// owner serves as it serves PCI_Config fields; `None`, reported once,
    /// when a read is refused.
    fn read_configuration(
        &self,
        pci: &native_mmio::Source,
        physical: u64,
        bytes: u64,
    ) -> Option<u64> {
        let read = ecam_memory::read(&self.ecam, physical, bytes, |address, offset, width| {
            pci.read_firmware_config(address, offset, width)
        });
        match read {
            Ok(value) => Some(value),
            Err(ecam_memory::Refusal::Config {
                address,
                offset,
                error,
            }) => {
                self.report(
                    Gap::EcamRead,
                    format_args!(
                        "native PCI read of {address} register {offset:#x} through ECAM at \
                         {physical:#x} refused: {error:?}"
                    ),
                );
                None
            }
            Err(ecam_memory::Refusal::Outside { physical: outside }) => {
                self.report(
                    Gap::EcamRead,
                    format_args!(
                        "AML read of {bytes} bytes at {physical:#x} leaves ECAM at {outside:#x}"
                    ),
                );
                None
            }
            Err(ecam_memory::Refusal::Width) => {
                self.report(
                    Gap::EcamRead,
                    format_args!("AML read of {bytes} bytes at {physical:#x} in ECAM"),
                );
                None
            }
        }
    }

    /// AML's write of `bytes` of `value` at `physical` in an ECAM window, as
    /// the configuration writes of the functions it decodes to, when writes
    /// are admitted before the census; false, reported once, when refused.
    fn write_configuration(
        &self,
        pci: &native_mmio::Source,
        physical: u64,
        bytes: u64,
        value: u64,
    ) -> bool {
        if !self.config_writes.get() {
            self.report(
                Gap::EcamWrite,
                format_args!(
                    "native PCI configuration excludes AML writes to ECAM at {physical:#x}"
                ),
            );
            return false;
        }
        let written = ecam_memory::write(
            &self.ecam,
            physical,
            bytes,
            value,
            |address, offset, width, piece| {
                pci.write_before_census(address, offset, width, piece)
                    .map_err(|error| (address, offset, error))
            },
        );
        if let Err(refusal) = written {
            self.report(
                Gap::PowerWrite,
                format_args!(
                    "AML write of {bytes} bytes at {physical:#x} in ECAM refused: {refusal:?}"
                ),
            );
            return false;
        }
        true
    }

    /// Whether the loader root maps `address`.
    fn mapped(&self, address: u64) -> bool {
        match tables::entry(&mut HeapFrames, self.root, address, 0, false) {
            // Only a 2 MiB page stops the walk early.
            Err(_) => true,
            // SAFETY: a live leaf slot of the loader root.
            Ok(slot) => slot.is_some_and(|slot| unsafe { slot.read_volatile() } & PRESENT != 0),
        }
    }

    /// The ECAM address of `register` in `id`'s configuration space.
    fn ecam(&self, id: &PciId, register: u32) -> Option<u64> {
        let bus = u8::try_from(id.bus).ok()?;
        let window = self.ecam.iter().find(|window| {
            window.segment == id.segment && (window.start_bus..=window.end_bus).contains(&bus)
        })?;
        (id.device < 32 && id.function < 8 && register < 4096).then(|| {
            window.base
                + (u64::from(bus) << 20
                    | u64::from(id.device) << 15
                    | u64::from(id.function) << 12
                    | u64::from(register))
        })
    }

    fn permits_port(&self, port: u16, width: u32) -> bool {
        let first = u32::from(port);
        if self.pci.is_some()
            && first < u32::from(PCI_DATA) + 4
            && first + width / 8 > u32::from(PCI_ADDRESS)
        {
            self.report(
                Gap::PciCustody,
                format_args!("native PCI configuration owns the legacy configuration ports"),
            );
            return false;
        }
        true
    }

    /// Milliseconds of the TSC, for the SCI's and the EC's guards.
    fn now_ms(&self) -> u64 {
        host::rdtsc() / (self.tsc_hz / 1000).max(1)
    }

    /// ACPICA's SCI handler, when the SCI's interrupt arrived or, while its
    /// storm guard keeps the line masked, every `POLL_MS`
    /// ([`SciGovernor`]); then the line rearmed, unless the guard keeps it
    /// masked, and with `work` the deferred work run.
    fn dispatch_sci(&self, work: bool) -> bool {
        if self.polling.replace(true) {
            return false;
        }
        let armed = self.sci.borrow_mut().take();
        let mut handled = false;
        let mut masked = false;
        if let Some(armed) = &armed {
            let now = self.now_ms();
            let mut governor = self
                .sci_governor
                .get()
                .unwrap_or_else(|| SciGovernor::new(now));
            let turn = governor.turn(now, armed.interrupted());
            self.sci_governor.set(Some(governor));
            masked = governor.polled();
            if let Some(change) = turn.change {
                output::arguments(format_args!("{}", change.line()));
                if masked {
                    output::arguments(format_args!(
                        "HOST ACPI SCI storm registers: {}\n",
                        armed.registers()
                    ));
                }
            }
            // While masked, and on the turn interrupts are tried again, the
            // handler runs with no interrupt pending: the line was masked, so
            // what asserted it since is read from the status registers, and
            // the rearm that follows needs that dispatch.
            let polled = masked || turn.change == Some(hardware_mode::Change::Retry);
            if turn.dispatch {
                match armed.dispatch(polled) {
                    Ok(dispatched) => {
                        handled = dispatched;
                        if dispatched && turn.rearm {
                            self.needs_rearm.set(true);
                        }
                    }
                    Err(error) => {
                        output::arguments(format_args!("HOST ACPI SCI failed: {error:?}\n"))
                    }
                }
            }
        }
        // ACPICA's ISR has acknowledged fixed events and disabled deferred
        // GPE contributors. Rearm the parent before executing AML: a worker
        // may wait for the FACS global-lock release fixed event on this SCI.
        // A line the storm guard keeps masked is not rearmed.
        if self.needs_rearm.get()
            && !masked
            && let Some(armed) = &armed
        {
            // SAFETY: the native IRQ returned/EOIed and the C ISR completed;
            // each deferred contributor owns its own disabled source until done.
            match unsafe { armed.rearm() } {
                Ok(()) => self.needs_rearm.set(false),
                Err(error) => {
                    output::arguments(format_args!("HOST ACPI SCI rearm failed: {error:?}\n"))
                }
            }
        }
        *self.sci.borrow_mut() = armed;
        self.polling.set(false);
        if work {
            // SAFETY: process queue owned by this provider, with no route or
            // queue borrow held across a worker's OSL semaphore waits.
            if unsafe { drain_work(core::ptr::from_ref(self).cast_mut().cast()) } != AE_OK {
                output::fatal("ACPI deferred work completion failed");
            }
        }
        handled
    }
    /// AML's Sleep. The running step's marker and seconds keep moving
    /// through it, as through the drivers' own waits: a table load that
    /// sleeps for seconds showed a still screen, which reads as a hang.
    fn milliseconds(&self, milliseconds: u64) {
        let start = host::rdtsc();
        let ticks = self.tsc_hz / 1000 * milliseconds;
        while host::rdtsc().wrapping_sub(start) < ticks {
            crate::status::tick();
            core::hint::spin_loop();
        }
    }
}

/// Page-table frames from the engine heap, which lies in the physmap.
struct HeapFrames;

impl Frames for HeapFrames {
    fn frame(&mut self) -> Option<u64> {
        let layout = Layout::from_size_align(PAGE as usize, PAGE as usize).ok()?;
        // SAFETY: a nonzero layout; the frame stays the loader root's.
        let page = unsafe { alloc::alloc::alloc_zeroed(layout) };
        (!page.is_null()).then(|| page as u64 - layout::physical(0))
    }

    fn table(&self, physical: u64) -> *mut u64 {
        layout::physical(physical) as *mut u64
    }
}

/// # Safety
/// `context` is the session's live [`Provider`].
unsafe fn provider<'a>(context: *mut c_void) -> &'a Provider {
    // SAFETY: the caller's contract.
    unsafe { &*context.cast::<Provider>() }
}

unsafe extern "C" fn allocate(_: *mut c_void, bytes: u64) -> *mut c_void {
    let Some(layout) = usize::try_from(bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(HEADER))
        .and_then(|total| Layout::from_size_align(total, HEADER).ok())
    else {
        return ptr::null_mut();
    };
    // SAFETY: a nonzero layout.
    let raw = unsafe { alloc::alloc::alloc(layout) };
    if raw.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the header lies in this allocation, which is aligned for it.
    unsafe {
        raw.cast::<usize>().write(layout.size());
        raw.add(HEADER).cast()
    }
}

unsafe extern "C" fn free(_: *mut c_void, allocation: *mut c_void) {
    // SAFETY: `allocate` returned `allocation`, its header just before it.
    unsafe {
        let raw = allocation.cast::<u8>().sub(HEADER);
        let size = raw.cast::<usize>().read();
        alloc::alloc::dealloc(raw, Layout::from_size_align_unchecked(size, HEADER));
    }
}

unsafe extern "C" fn map(context: *mut c_void, physical: u64, bytes: u64) -> *mut c_void {
    // SAFETY: ACPICA passes the session's provider.
    unsafe { provider(context) }
        .reach(physical, bytes)
        .map_or(ptr::null_mut(), |pointer| pointer.cast())
}

/// The lease ends; the mapping stays the loader root's, as the identity
/// map's other pages do, for the next lease of the same registers.
unsafe extern "C" fn unmap(_: *mut c_void, _: *mut c_void, _: u64) {}

unsafe extern "C" fn create_lock(_: *mut c_void, out: *mut *mut c_void) -> Status {
    // SAFETY: ACPICA's writable output.
    unsafe { out.write(Box::into_raw(Box::new(AtomicBool::new(false))).cast()) };
    AE_OK
}

unsafe extern "C" fn delete_lock(_: *mut c_void, lock: *mut c_void) {
    // SAFETY: `create_lock` made `lock`, which ACPICA deletes once.
    drop(unsafe { Box::from_raw(lock.cast::<AtomicBool>()) });
}

unsafe extern "C" fn acquire_lock(_: *mut c_void, lock: *mut c_void) -> u64 {
    let flags: u64;
    // SAFETY: CPL0; `release_lock` restores IF.
    unsafe { asm!("pushfq", "pop {}", "cli", out(reg) flags, options(nomem)) };
    // SAFETY: a lock `create_lock` made.
    let lock = unsafe { &*lock.cast::<AtomicBool>() };
    while lock
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    flags
}

unsafe extern "C" fn release_lock(_: *mut c_void, lock: *mut c_void, flags: u64) {
    // SAFETY: a lock `create_lock` made.
    unsafe { &*lock.cast::<AtomicBool>() }.store(false, Ordering::Release);
    if flags & INTERRUPTS != 0 {
        // SAFETY: `acquire_lock` cleared IF, which was set.
        unsafe { asm!("sti", options(nomem, nostack)) };
    }
}

struct Semaphore {
    units: AtomicU32,
    max: u32,
}

unsafe extern "C" fn create_semaphore(
    _: *mut c_void,
    max: u32,
    initial: u32,
    out: *mut *mut c_void,
) -> Status {
    if max == 0 || initial > max {
        return AE_BAD_PARAMETER;
    }
    let semaphore = Semaphore {
        units: AtomicU32::new(initial),
        max,
    };
    // SAFETY: ACPICA's writable output.
    unsafe { out.write(Box::into_raw(Box::new(semaphore)).cast()) };
    AE_OK
}

unsafe extern "C" fn delete_semaphore(_: *mut c_void, semaphore: *mut c_void) -> Status {
    // SAFETY: `create_semaphore` made it, and ACPICA deletes it once.
    drop(unsafe { Box::from_raw(semaphore.cast::<Semaphore>()) });
    AE_OK
}

unsafe extern "C" fn wait_semaphore(
    context: *mut c_void,
    semaphore: *mut c_void,
    units: u32,
    timeout: u16,
) -> Status {
    // SAFETY: ACPICA passes the session's provider and a live semaphore.
    let (provider, semaphore) = unsafe { (provider(context), &*semaphore.cast::<Semaphore>()) };
    if units == 0 || units > semaphore.max {
        return AE_BAD_PARAMETER;
    }
    let take = || {
        semaphore
            .units
            .try_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_sub(units)
            })
            .is_ok()
    };
    if take() {
        return AE_OK;
    }
    if timeout == 0 {
        return AE_TIME;
    }
    // Only ACPICA's SCI work, on this one processor, signals a semaphore
    // while AML waits: without it no wait, however long, can end, and one
    // of 0xFFFE ms (an Acquire or Wait short of forever) would only spin.
    if provider.sci.borrow().is_none() {
        provider.report(
            Gap::Wait,
            format_args!("semaphore wait has no interrupt progress source"),
        );
        return AE_TIME;
    }
    let start = host::rdtsc();
    let ticks = provider.tsc_hz / 1000 * u64::from(timeout);
    loop {
        if take() {
            return AE_OK;
        }
        if timeout != WAIT_FOREVER && host::rdtsc().wrapping_sub(start) >= ticks {
            break;
        }
        if let Ok(platform) = crate::native_irq::NativePlatform::current() {
            // SAFETY: current BSP and provider root are held through this
            // wait; only the small native IRQ handlers run in this window.
            unsafe { stela_drivers::bus::irq::Platform::interrupt_window(&platform) };
            provider.dispatch_sci(false);
        }
        core::hint::spin_loop();
    }
    AE_TIME
}

unsafe extern "C" fn signal_semaphore(
    _: *mut c_void,
    semaphore: *mut c_void,
    units: u32,
) -> Status {
    // SAFETY: a live semaphore `create_semaphore` made.
    let semaphore = unsafe { &*semaphore.cast::<Semaphore>() };
    match semaphore
        .units
        .try_update(Ordering::AcqRel, Ordering::Acquire, |held| {
            held.checked_add(units)
                .filter(|&next| next <= semaphore.max)
        }) {
        Ok(_) => AE_OK,
        Err(_) => AE_LIMIT,
    }
}

unsafe extern "C" fn install_interrupt(
    context: *mut c_void,
    irq: u32,
    handler: Interrupt,
    argument: *mut c_void,
) -> Status {
    // SAFETY: this live provider is held by the active ACPICA session.
    let provider = unsafe { provider(context) };
    let Some(prepared) = provider.prepared_sci.borrow_mut().take() else {
        return AE_SUPPORT;
    };
    if prepared.irq() != irq {
        return AE_BAD_PARAMETER;
    }
    // SAFETY: ACPICA's permanent SCI handler/context and exclusive boot route.
    match unsafe { prepared.install(handler, argument) } {
        Ok(armed) => {
            *provider.sci.borrow_mut() = Some(armed);
            AE_OK
        }
        Err(error) => {
            output::arguments(format_args!("HOST ACPI SCI install failed: {error:?}\n"));
            AE_ERROR
        }
    }
}
unsafe extern "C" fn remove_interrupt(context: *mut c_void, _: u32, _: Interrupt) -> Status {
    // SAFETY: the session's provider; process context at termination.
    let provider = unsafe { provider(context) };
    let mut slot = provider.sci.borrow_mut();
    match slot.as_mut() {
        None => AE_NOT_EXIST,
        Some(armed) => match armed.retire() {
            Ok(()) => {
                slot.take();
                AE_OK
            }
            Err(_) => AE_ERROR,
        },
    }
}

/// ACPICA mutex ownership uses the continuation identity.
unsafe extern "C" fn thread_id(context: *mut c_void) -> u64 {
    // SAFETY: this Session keeps its provider and real affine work owner.
    let provider = unsafe { provider(context) };
    provider
        .executor
        .current_id()
        .unwrap_or_else(|_| output::fatal("ACPICA called outside its owned native continuation"))
}

unsafe extern "C" fn execute(
    context: *mut c_void,
    _: u32,
    work: Work,
    argument: *mut c_void,
) -> Status {
    // SAFETY: ACPICA passes the session's provider.
    let provider = unsafe { provider(context) };
    if provider.closed.get() {
        return AE_NOT_EXIST;
    }
    provider
        .work
        .borrow_mut()
        .push_back((work, argument as usize));
    provider.queued.store(true, Ordering::Release);
    AE_OK
}

unsafe extern "C" fn drain_work(context: *mut c_void) -> Status {
    // SAFETY: ACPICA passes the session's provider.
    let provider = unsafe { provider(context) };
    loop {
        let next = provider.work.borrow_mut().pop_front();
        let Some((work, argument)) = next else {
            provider.queued.store(false, Ordering::Release);
            return AE_OK;
        };
        // SAFETY: ACPICA queued this work with its argument.
        unsafe { work(argument as *mut c_void) };
    }
}

unsafe extern "C" fn sleep(context: *mut c_void, milliseconds: u64) {
    // SAFETY: ACPICA passes the session's provider.
    unsafe { provider(context) }.milliseconds(milliseconds);
}

unsafe extern "C" fn stall(context: *mut c_void, microseconds: u32) {
    // SAFETY: ACPICA passes the session's provider.
    let provider = unsafe { provider(context) };
    let start = host::rdtsc();
    let ticks = provider.tsc_hz / 1_000_000 * u64::from(microseconds);
    while host::rdtsc().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
    // After the stall, whose length AML chose: a loop of short stalls
    // keeps the running step's marker moving.
    crate::status::tick();
}

unsafe extern "C" fn read_port(
    context: *mut c_void,
    port: u64,
    value: *mut u32,
    width: u32,
) -> Status {
    let Ok(port) = u16::try_from(port) else {
        return AE_BAD_PARAMETER;
    };
    if !matches!(width, 8 | 16 | 32) {
        return AE_BAD_PARAMETER;
    }
    // SAFETY: ACPICA passes the session's provider.
    if !unsafe { provider(context) }.permits_port(port, width) {
        return AE_SUPPORT;
    }
    // SAFETY: the firmware's AML or FADT names the port; ACPICA screens it
    // as Linux's does; the output is writable.
    unsafe {
        value.write(match width {
            8 => in8(port).into(),
            16 => in16(port).into(),
            32 => in32(port),
            _ => unreachable!("port width was checked"),
        })
    };
    AE_OK
}

unsafe extern "C" fn write_port(context: *mut c_void, port: u64, value: u32, width: u32) -> Status {
    let Ok(port) = u16::try_from(port) else {
        return AE_BAD_PARAMETER;
    };
    if !matches!(width, 8 | 16 | 32) {
        return AE_BAD_PARAMETER;
    }
    // SAFETY: ACPICA passes the session's provider.
    let provider = unsafe { provider(context) };
    if !provider.permits_port(port, width) {
        return AE_SUPPORT;
    }
    // A write to `SMI_CMD` enters the firmware's system management code,
    // which no watchdog of Stela's can end: the screen names the method
    // until it returns, and the log how long it took and where the other
    // processors were.
    let smi = (provider.smi_command == Some(port)).then(|| {
        // SAFETY: inside ACPICA, on its only processor, between its calls.
        let by = unsafe { stela_drivers::platform::acpi::running() }.map_or_else(
            || alloc::string::String::from("ACPICA itself"),
            |at| alloc::string::String::from(at.method.as_str()),
        );
        let detail = crate::status::detail();
        crate::status::progress(&alloc::format!(
            "{detail}: {by} calls the firmware's system management code"
        ));
        (by, detail, host::rdtsc())
    });
    // SAFETY: as in `read_port`.
    unsafe {
        match width {
            8 => out8(port, value as u8),
            16 => out16(port, value as u16),
            32 => out32(port, value),
            _ => unreachable!("port width was checked"),
        }
    }
    if let Some((by, detail, started)) = smi {
        let micros = host::rdtsc().wrapping_sub(started) / (provider.tsc_hz / 1_000_000).max(1);
        let mut writes = provider.smi_writes.get();
        let line = writes.record(
            port,
            value,
            &by,
            micros,
            crate::native_smp::executor::others(),
        );
        provider.smi_writes.set(writes);
        if let Some(line) = line {
            output::arguments(format_args!("{line}"));
        }
        crate::status::progress(&detail);
    }
    AE_OK
}

/// # Safety
/// `pointer` reaches `width` bits the firmware names.
unsafe fn read(pointer: *mut u8, width: u32) -> Option<u64> {
    // SAFETY: the caller's contract.
    unsafe {
        Some(match width {
            8 => pointer.read_volatile().into(),
            16 => pointer.cast::<u16>().read_volatile().into(),
            32 => pointer.cast::<u32>().read_volatile().into(),
            64 => pointer.cast::<u64>().read_volatile(),
            _ => return None,
        })
    }
}

/// # Safety
/// As [`read`].
unsafe fn write(pointer: *mut u8, value: u64, width: u32) -> bool {
    // SAFETY: the caller's contract.
    unsafe {
        match width {
            8 => pointer.write_volatile(value as u8),
            16 => pointer.cast::<u16>().write_volatile(value as u16),
            32 => pointer.cast::<u32>().write_volatile(value as u32),
            64 => pointer.cast::<u64>().write_volatile(value),
            _ => return false,
        }
    }
    true
}

/// A hardware register or an AML SystemMemory field: the bridge routes
/// every SystemMemory region access here.
unsafe extern "C" fn read_memory(
    context: *mut c_void,
    physical: u64,
    value: *mut u64,
    width: u32,
) -> Status {
    // SAFETY: ACPICA passes the session's provider.
    let provider = unsafe { provider(context) };
    if !matches!(width, 8 | 16 | 32 | 64) {
        return AE_BAD_PARAMETER;
    }
    let bytes = u64::from(width / 8);
    let found = if let Some(pci) = provider.configuration_owner(physical, bytes) {
        provider.read_configuration(pci, physical, bytes)
    } else {
        let Some(pointer) = provider.reach(physical, bytes) else {
            return AE_ERROR;
        };
        // SAFETY: the firmware's register, now mapped; the width was checked.
        unsafe { read(pointer, width) }
    };
    let Some(found) = found else {
        return AE_SUPPORT;
    };
    // SAFETY: ACPICA's writable output.
    unsafe { value.write(found) };
    AE_OK
}

/// As [`read_memory`]. Native PCI custody excludes AML configuration
/// writes, through ECAM as through PCI_Config fields ([`write_pci`]),
/// except while they are admitted before the census.
unsafe extern "C" fn write_memory(
    context: *mut c_void,
    physical: u64,
    value: u64,
    width: u32,
) -> Status {
    // SAFETY: ACPICA passes the session's provider.
    let provider = unsafe { provider(context) };
    if !matches!(width, 8 | 16 | 32 | 64) {
        return AE_BAD_PARAMETER;
    }
    if let Some(pci) = provider.configuration_owner(physical, u64::from(width / 8)) {
        return match provider.write_configuration(pci, physical, u64::from(width / 8), value) {
            true => AE_OK,
            false => AE_SUPPORT,
        };
    }
    let Some(pointer) = provider.reach(physical, u64::from(width / 8)) else {
        return AE_ERROR;
    };
    // SAFETY: the firmware's register, now mapped.
    match unsafe { write(pointer, value, width) } {
        true => AE_OK,
        false => AE_BAD_PARAMETER,
    }
}

/// Configuration mechanism #1's address, as Linux's `PCI_CONF1_ADDRESS`,
/// for segment 0's first 256 registers.
fn mechanism_one(id: &PciId, register: u32) -> Option<u32> {
    (id.segment == 0 && id.bus < 256 && id.device < 32 && id.function < 8 && register < 256).then(
        || {
            0x8000_0000
                | u32::from(id.bus) << 16
                | u32::from(id.device) << 11
                | u32::from(id.function) << 8
                | register & 0xfc
        },
    )
}

/// The function and register a PCI_Config access names, when they fit.
fn native_address(id: &PciId, register: u32) -> Option<(Address, u16)> {
    Some((
        Address {
            segment: id.segment,
            bus: u8::try_from(id.bus).ok()?,
            device: u8::try_from(id.device).ok()?,
            function: u8::try_from(id.function).ok()?,
        },
        u16::try_from(register).ok()?,
    ))
}

unsafe extern "C" fn read_pci(
    context: *mut c_void,
    id: *mut PciId,
    register: u32,
    value: *mut u64,
    width: u32,
) -> Status {
    // SAFETY: ACPICA passes the session's provider and a live identity.
    let (provider, id) = unsafe { (provider(context), &*id) };
    if !matches!(width, 8 | 16 | 32) {
        return AE_ERROR;
    }
    let read = if let Some(pci) = provider.pci {
        let Some((address, offset)) = native_address(id, register) else {
            return AE_BAD_PARAMETER;
        };
        match pci.read_firmware_config(address, offset, (width / 8) as u16) {
            Ok(value) => u64::from(value),
            Err(error) => {
                provider.report(
                    Gap::Config,
                    format_args!(
                        "native PCI read of {address} register {offset:#x} refused: {error:?}"
                    ),
                );
                return AE_SUPPORT;
            }
        }
    } else if let Some(address) = mechanism_one(id, register) {
        let port = PCI_DATA + (register & 3) as u16;
        // SAFETY: mechanism #1's ports, under the host drivers' lock.
        unsafe {
            out32(PCI_ADDRESS, address);
            match width {
                8 => u64::from(in8(port)),
                16 => u64::from(in16(port & !1)),
                _ => u64::from(in32(PCI_DATA)),
            }
        }
    } else {
        let Some(pointer) = provider
            .ecam(id, register)
            .and_then(|address| provider.reach(address, u64::from(width / 8)))
        else {
            provider.report(
                Gap::Config,
                format_args!(
                    "configuration space {id:?} register {register:#x} has no ECAM window"
                ),
            );
            return AE_SUPPORT;
        };
        // SAFETY: an ECAM register, mapped uncached.
        unsafe { read(pointer, width) }.unwrap_or_default()
    };
    // SAFETY: ACPICA's writable output.
    unsafe { value.write(read) };
    AE_OK
}

unsafe extern "C" fn write_pci(
    context: *mut c_void,
    id: *mut PciId,
    register: u32,
    value: u64,
    width: u32,
) -> Status {
    // SAFETY: ACPICA passes the session's provider and a live identity.
    let (provider, id) = unsafe { (provider(context), &*id) };
    if !matches!(width, 8 | 16 | 32) {
        return AE_ERROR;
    }
    if let Some(pci) = provider.pci {
        if !provider.config_writes.get() {
            provider.report(
                Gap::PciCustody,
                format_args!("native PCI configuration excludes AML writes"),
            );
            return AE_SUPPORT;
        }
        let Some((address, offset)) = native_address(id, register) else {
            return AE_BAD_PARAMETER;
        };
        return match pci.write_before_census(address, offset, (width / 8) as u16, value as u32) {
            Ok(()) => AE_OK,
            Err(error) => {
                provider.report(
                    Gap::PowerWrite,
                    format_args!(
                        "native PCI write of {address} register {offset:#x} refused: {error:?}"
                    ),
                );
                AE_SUPPORT
            }
        };
    }
    if let Some(address) = mechanism_one(id, register) {
        let port = PCI_DATA + (register & 3) as u16;
        // SAFETY: mechanism #1's ports, under the host drivers' lock.
        unsafe {
            out32(PCI_ADDRESS, address);
            match width {
                8 => out8(port, value as u8),
                16 => out16(port & !1, value as u16),
                _ => out32(PCI_DATA, value as u32),
            }
        }
        return AE_OK;
    }
    let Some(pointer) = provider
        .ecam(id, register)
        .and_then(|address| provider.reach(address, u64::from(width / 8)))
    else {
        provider.report(
            Gap::Config,
            format_args!("configuration space {id:?} register {register:#x} has no ECAM window"),
        );
        return AE_SUPPORT;
    };
    // SAFETY: an ECAM register, mapped uncached.
    unsafe { write(pointer, value, width) };
    AE_OK
}

/// 100 ns units, from the TSC. Every AML loop and wait reads it for its
/// bound, so the running step's marker moves from here through a long
/// method that neither sleeps nor stalls.
unsafe extern "C" fn timer(context: *mut c_void) -> u64 {
    crate::status::tick();
    // SAFETY: ACPICA passes the session's provider.
    let hz = unsafe { provider(context) }.tsc_hz;
    (u128::from(host::rdtsc()) * 10_000_000 / u128::from(hz)) as u64
}

/// As Linux's `acpi_os_signal`: AML's Fatal is reported, and execution
/// goes on; a breakpoint is ignored.
unsafe extern "C" fn signal(_: *mut c_void, kind: u32, info: *mut c_void) -> Status {
    if kind == SIGNAL_FATAL && !info.is_null() {
        // SAFETY: ACPICA's `acpi_signal_fatal_info`: type, code, argument.
        let [kind, code, argument] = unsafe { info.cast::<[u32; 3]>().read() };
        output::arguments(format_args!(
            "ACPI firmware AML Fatal type={kind:#x} code={code:#x} argument={argument:#x}\n"
        ));
    }
    AE_OK
}

unsafe extern "C" fn log(_: *mut c_void, text: *const c_char, bytes: u64) {
    // SAFETY: ACPICA's formatted message of `bytes` bytes.
    let text = unsafe { core::slice::from_raw_parts(text.cast::<u8>(), bytes as usize) };
    output::arguments(format_args!("{}", String::from_utf8_lossy(text)));
}

unsafe extern "C" fn flush_cache(_: *mut c_void) {
    // SAFETY: CPL0; writes back and invalidates the caches.
    unsafe { asm!("wbinvd", options(nostack, preserves_flags)) };
}

/// No SCI or region callback runs beside AML: closing admission and running
/// the queued work quiesces the session.
unsafe extern "C" fn quiesce(context: *mut c_void) -> Status {
    // SAFETY: ACPICA passes the session's provider.
    let provider = unsafe { provider(context) };
    provider.closed.set(true);
    if let Some(armed) = provider.sci.borrow_mut().as_mut()
        && armed.retire().is_err()
    {
        return AE_ERROR;
    }
    // SAFETY: as above.
    unsafe { drain_work(context) }
}

/// Immediate eligibility only: this checks the real current continuation and
/// reserved firmware-role contract before C removes any callback. The current
/// legacy constructor refuses; it does not acquire permission from an empty FIFO.
unsafe extern "C" fn preflight_wait_events(context: *mut c_void) -> Status {
    // SAFETY: Session keeps this provider and its affine executor.
    match unsafe { provider(context) }.executor.check_firmware_wait() {
        Ok(()) => AE_OK,
        Err(_) => AE_SUPPORT,
    }
}

unsafe extern "C" fn destroy(context: *mut c_void) {
    // SAFETY: the session's provider, which `HostAcpi::start` leaked to it.
    drop(unsafe { Box::from_raw(context.cast::<Provider>()) });
}

unsafe extern "C" fn fatal(_: *mut c_void, status: Status) -> ! {
    output::fatal(format_args!(
        "ACPI callback completion failed: ACPICA status {status:#x}"
    ))
}

/// The firmware's ACPI namespace, for the host's power transitions.
/// One namespace serves the whole program: [`HostAcpi::start`] leaks it, and
/// the host drivers and power transitions borrow it for `'static`.
pub struct HostAcpi {
    session: Session,
    provider: *const Provider,
    /// The services the namespace was loaded with; nonzero admits hardware
    /// mode ([`Self::activate`]).
    capabilities: u64,
    ec: RefCell<Option<stela_drivers::platform::ec::binding::Binding<'static>>>,
    installed_ec: RefCell<Option<stela_drivers::platform::ec::capability::Installed<'static>>>,
    power: RefCell<stela_drivers::probe::Power>,
    notification: RefCell<Option<stela_drivers::platform::acpi::Notification<'static>>>,
    /// The control-method power buttons whose presses set [`BUTTON_NOTIFIED`].
    buttons: RefCell<Vec<stela_drivers::platform::button::PowerButton<'static>>>,
    /// The lid's notify handler, which counts in [`LID_NOTIFIED`].
    lid_notification: RefCell<Option<stela_drivers::platform::acpi::Notification<'static>>>,
    /// The display outputs whose brightness notifications set [`BRIGHTNESS`].
    backlights: RefCell<
        Vec<(
            stela_drivers::probe::backlight::Control<'static>,
            stela_drivers::platform::acpi::Notification<'static>,
        )>,
    >,
    /// The ASUS WMI device, and the notify handler that counts its events
    /// in [`ASUS_EVENTS`].
    asus: RefCell<
        Option<(
            stela_drivers::platform::asus_wmi::AsusWmi<'static>,
            stela_drivers::platform::acpi::Notification<'static>,
        )>,
    >,
    ec_pending: Cell<bool>,
    /// The EC's query budget and failure breaker, from its first event.
    ec_governor: RefCell<Option<EcGovernor>>,
    hardware: AtomicBool,
    ec_failed: AtomicBool,
    deferred_failed: AtomicBool,
}
static EC_EVENT: AtomicBool = AtomicBool::new(false);
static POWER_CHANGED: AtomicBool = AtomicBool::new(false);
/// A timed reading of the batteries' state and the AC adapter is due.
static POWER_POLL: AtomicBool = AtomicBool::new(false);
static POWER_BUTTON: AtomicBool = AtomicBool::new(false);
/// A control-method power button's (PNP0C0C) notifications since the power
/// control took them: a FADT with PWR_BUTTON set reports presses so.
static BUTTON_NOTIFIED: AtomicU32 = AtomicU32::new(0);
/// The lid's STATUS notifications since the poll took them
/// ([`HostAcpi::service_lid`]).
static LID_NOTIFIED: AtomicU32 = AtomicU32::new(0);
/// The display outputs with `_BCL` and `_BCM` whose brightness keys are
/// followed, at most.
const BACKLIGHTS: usize = 8;
/// Each followed output's last brightness notification since the poll
/// took it, 0 for none ([`HostAcpi::service_brightness`]).
static BRIGHTNESS: [AtomicU32; BACKLIGHTS] = [const { AtomicU32::new(0) }; BACKLIGHTS];
/// The last brightness notification of any device since the poll took it.
static BRIGHTNESS_SEEN: AtomicU32 = AtomicU32::new(0);
/// `--brightness-keys`: the brightness notifications are followed.
static BRIGHTNESS_KEYS: AtomicBool = AtomicBool::new(false);

/// Follow the brightness notifications (`--brightness-keys`).
pub(super) fn follow_brightness_keys(on: bool) {
    BRIGHTNESS_KEYS.store(on, Ordering::Release);
}
/// The ASUS WMI event notifications since the poll took them; any number of
/// them has the poll drain the firmware's queue
/// ([`HostAcpi::service_asus_wmi`]).
static ASUS_EVENTS: AtomicU32 = AtomicU32::new(0);
/// The ASUS WMI events one poll reads at most: twice what the FA608PP's
/// queue holds (16), so a queue that never reads empty still ends.
const ASUS_DRAIN: usize = 32;

impl HostAcpi {
    /// Load the tables at `rsdp` and their namespace, in interpreter mode;
    /// `None`, reported, when ACPICA refuses them. `root` is the loader
    /// root. The namespace lives until the host powers off, so it is leaked
    /// here, once. Hardware mode follows the PCI census ([`Self::activate`]),
    /// where `hardware` (`--acpi-hardware`) admits it.
    pub(super) fn start(
        rsdp: u64,
        root: u64,
        mut ecam: Vec<EcamWindow>,
        pci: Option<&'static native_mmio::Source>,
        tsc_hz: u64,
        executor: Option<&'static KernelWork>,
        hardware: bool,
    ) -> Option<&'static Self> {
        let Some(executor) = executor else {
            output::arguments(format_args!(
                "ACPI firmware AML unavailable: native continuation owner is unavailable\n"
            ));
            return None;
        };
        let pci = if let Some(source) = pci {
            match source.configuration_windows() {
                Ok(windows) if windows.is_empty() => None,
                Ok(windows) => {
                    ecam = windows;
                    Some(source)
                }
                Err(error) => {
                    output::arguments(format_args!(
                        "ACPI firmware AML unavailable: native PCI configuration inventory refused ({error:?})\n"
                    ));
                    return None;
                }
            }
        } else {
            None
        };
        match executor.call_owned(5_000_000, move || {
            Self::start_entered(rsdp, root, ecam, pci, tsc_hz, executor, hardware)
        }) {
            Ok(acpi) => acpi,
            Err(error) => {
                output::arguments(format_args!(
                    "ACPI firmware AML admission failed: {error}\n"
                ));
                None
            }
        }
    }
    /// Called only by the owned foreground callback under its kept
    /// loader-root/host-driver guard. It must never acquire that guard again.
    fn start_entered(
        rsdp: u64,
        root: u64,
        ecam: Vec<EcamWindow>,
        pci: Option<&'static native_mmio::Source>,
        tsc_hz: u64,
        executor: &'static KernelWork,
        hardware: bool,
    ) -> Option<&'static Self> {
        if rsdp == 0 {
            output::arguments(format_args!("ACPI firmware AML unavailable: no RSDP\n"));
            return None;
        }
        // An SCI route alone does not check ACPICA hardware mode, which is
        // off unless `--acpi-hardware` asks for it until a laptop has proven
        // it. With it, the provider attests its services: the SCI through
        // the owned IOAPIC route (`sci`), deferred work on this continuation
        // (`execute`, `drain_work`), the EC's region handler installed before
        // hardware activation runs `_REG`, and allocations from the heap,
        // which ACPICA's handler reaches only on this continuation, never in
        // the hard interrupt (`sci::Deferred` only masks and flags). ACPICA's
        // `map` leases stay the loader root's for good, which a namespace
        // that lives until power-off never gives back.
        let capabilities = if hardware { FULL_CAPABILITIES } else { 0 };
        let provider = Box::new(Provider {
            executor,
            root,
            ecam,
            pci,
            tsc_hz,
            work: RefCell::new(VecDeque::new()),
            queued: AtomicBool::new(false),
            closed: Cell::new(false),
            reported: Cell::new(0),
            prepared_sci: RefCell::new(None),
            sci: RefCell::new(None),
            sci_governor: Cell::new(None),
            polling: Cell::new(false),
            needs_rearm: Cell::new(false),
            config_writes: Cell::new(false),
            smi_command: pci.and_then(|pci| stela_boot_core::smi::command_port(pci.fadt())),
            smi_writes: Cell::new(Default::default()),
        });
        let provider = Box::into_raw(provider);
        let services = Services {
            abi_version: SERVICES_ABI_VERSION,
            abi_bytes: SERVICES_ABI_BYTES,
            context: provider.cast(),
            root: rsdp,
            capabilities,
            allocate,
            free,
            map,
            unmap,
            create_lock,
            delete_lock,
            acquire_lock,
            release_lock,
            create_semaphore,
            delete_semaphore,
            wait_semaphore,
            signal_semaphore,
            install_interrupt,
            remove_interrupt,
            thread_id,
            execute,
            drain_work,
            sleep,
            stall,
            read_port,
            write_port,
            read_memory,
            write_memory,
            read_pci,
            write_pci,
            timer,
            signal,
            log,
            flush_cache,
            quiesce,
            destroy,
            fatal,
            preflight_wait_events,
        };
        // The tables' module-level code and the namespace's initialization
        // run inside the start, and the bound covers them: firmware AML that
        // never finishes leaves the AML unloaded, as one the interpreter
        // refuses does, instead of a boot that hangs at this step.
        let (started, finished) = bounded(
            "firmware AML load",
            "the firmware's AML is not loaded",
            || {
                // SAFETY: every callback keeps the OSL contract above, the
                // provider is the session's, and only this processor runs ACPICA.
                let session = unsafe { Session::start(services, Mode::InterpreterOnly) }?;
                let s5 = Self::describe_s5(&session);
                Ok::<_, stela_drivers::platform::acpi::Error>((session, s5))
            },
        );
        let session = match started {
            Ok((session, s5)) if finished => {
                output::arguments(format_args!("ACPI firmware AML loaded: {s5}\n"));
                session
            }
            // Its namespace is left as the aborted methods left it: the
            // session stops, and with it the provider.
            Ok((session, _)) => {
                drop(session);
                return None;
            }
            Err(error) => {
                output::arguments(format_args!(
                    "ACPI firmware AML refused: ACPICA status {:#x}\n",
                    error.0
                ));
                return None;
            }
        };
        Some(Box::leak(Box::new(Self {
            session,
            provider,
            capabilities,
            ec: RefCell::new(None),
            installed_ec: RefCell::new(None),
            power: RefCell::new(Default::default()),
            notification: RefCell::new(None),
            buttons: RefCell::new(Vec::new()),
            lid_notification: RefCell::new(None),
            backlights: RefCell::new(Vec::new()),
            asus: RefCell::new(None),
            ec_pending: Cell::new(false),
            ec_governor: RefCell::new(None),
            hardware: AtomicBool::new(false),
            ec_failed: AtomicBool::new(false),
            deferred_failed: AtomicBool::new(false),
        })))
    }

    /// The namespace's device initialization in namespace mode: `\_INI`,
    /// `\_SB._INI`, then `_STA` and `_INI` of every present device, which an
    /// operating system runs before it looks for a device and hardware mode
    /// ([`Self::activate`]) runs itself. Firmware records there which
    /// operating system `_OSI` found and sets devices' pins and addresses;
    /// without it a laptop's touchpad `_CRS` holds no I2C connection. It
    /// runs before the PCI census, where AML may write PCI configuration as
    /// it does under Linux, bounded like every firmware call, and reported.
    /// It runs with `--acpi-hardware` too, so the census sees what it sees
    /// without it; hardware activation then runs no `_INI` again, and the
    /// EC's `_REG` follows `_INI`, as under Linux without an ECDT.
    pub(super) fn initialize_devices(&'static self) {
        match self.firmware(
            "device initialization",
            "devices are described as far as it got",
            true,
            |session| session.initialize_devices(),
        ) {
            Some(Ok(())) => {
                output::arguments(format_args!("ACPI firmware devices initialized (_INI)\n"));
            }
            Some(Err(error)) => output::arguments(format_args!(
                "UNSUPPORTED ACPI device initialization: {error}; devices are described as for an \
                 operating system without ACPI support\n"
            )),
            // Reported by the bounded call.
            None => {}
        }
    }

    /// Hardware mode, once the PCI census and containment have taken the
    /// SCI's route: `prepared_sci`, which an interpreter-only namespace
    /// drops. Reported either way.
    pub(super) fn activate(&'static self, prepared_sci: Option<sci::Prepared>) {
        if self.capabilities == 0 {
            // No hardware callback may take the route in namespace mode: it
            // is dropped here. The line names the option that turns it on.
            output::arguments(format_args!("{}", hardware_mode::off_line()));
            return;
        }
        let Some(prepared) = prepared_sci else {
            output::arguments(format_args!(
                "{}",
                hardware_mode::refused_line(
                    "the SCI's route was not captured (no contained PCI fabric, no FADT power \
                     registers, or the HOST ACPI SCI unavailable line's cause)"
                )
            ));
            return;
        };
        // SAFETY: this permanent provider is held by the leaked Session.
        let provider = unsafe { &*self.provider };
        let registers = provider
            .pci
            .and_then(|pci| hardware_mode::Registers::read(pci.fadt()));
        if let Some(registers) = registers {
            // SAFETY: the FADT's PM1a control port, whose read changes
            // nothing; ACPICA reads it itself before it writes SMI_CMD.
            let control = registers.control_port().map(|port| unsafe { in16(port) });
            output::arguments(format_args!(
                "{}",
                hardware_mode::starting_line(&registers, &prepared.route(), control)
            ));
        }
        // Bounded as every firmware call is, and given that bound's time:
        // `_REG` and ACPICA's wait for SCI_EN after SMI_CMD (3 s) are the
        // firmware's to make slow, and a continuation past its deadline
        // closes the work owner's entry for every later firmware call.
        let timeout = u64::from(AML_BOUND_MS) * 1000 + 1_000_000;
        if let Err(error) = provider.executor.call_owned(timeout, move || {
            bounded(
                "hardware activation",
                "ACPI hardware mode is left as far as it got",
                || self.activate_entered(Some(prepared)),
            )
        }) {
            output::arguments(format_args!(
                "UNSUPPORTED ACPI hardware activation: continuation unavailable: {error}\n"
            ));
            return;
        }
        if self.hardware_active() {
            self.attach_laptop_controls();
        }
    }

    /// Once the ACPI events are on, the brightness keys' outputs and the
    /// ASUS WMI device, each in its own bounded firmware call ([`bounded`])
    /// after the activation's, whose bound ends what was left of it: their
    /// methods (`_BCL`, `_BCM`, INIT and the keyboard backlight's) are the
    /// firmware's to make slow, and so can cost only what they attach, not
    /// the notifications and GPEs every device's events need.
    fn attach_laptop_controls(&'static self) {
        self.firmware(
            "brightness key attachment",
            "the outputs it reached are followed",
            false,
            move |_| self.attach_backlights(),
        );
        self.firmware(
            "ASUS WMI attachment",
            "its hotkeys are followed as far as it got",
            false,
            move |_| self.attach_asus_wmi(),
        );
    }
    /// The brightness keys' outputs, for `--brightness-keys` a laptop took
    /// after hardware mode started (`stela_boot_core::laptop`): attached
    /// as [`Self::attach_laptop_controls`] attaches them with the option,
    /// in their own bounded firmware call, where hardware mode runs.
    pub(super) fn attach_brightness_keys(&'static self) {
        if !self.hardware_active() {
            return;
        }
        self.firmware(
            "brightness key attachment",
            "the outputs it reached are followed",
            false,
            move |_| self.attach_backlights(),
        );
    }
    fn activate_entered(&'static self, prepared_sci: Option<sci::Prepared>) {
        // SAFETY: this permanent provider is held by the leaked Session.
        let provider = unsafe { &*self.provider };
        *provider.prepared_sci.borrow_mut() = prepared_sci;
        // SAFETY: the boot keeps the provider's exclusive EC resources
        // before namespace initialization and through this permanent owner.
        let installation =
            unsafe { stela_drivers::probe::install_embedded_controller(&self.session) };
        self.ec_failed
            .store(!installation.failures.is_empty(), Ordering::Release);
        for (location, error) in installation.failures {
            output::arguments(format_args!("HOST ACPI EC {location}: {error}\n"));
        }
        *self.ec.borrow_mut() = installation.binding;
        match self.session.enable_hardware() {
            Ok(()) => {
                self.hardware.store(true, Ordering::Release);
                if let Some(binding) = self.ec.borrow().as_ref() {
                    match stela_drivers::platform::ec::capability::Installed::from_binding(binding)
                    {
                        Ok(installed) => *self.installed_ec.borrow_mut() = Some(installed),
                        Err(error) => output::arguments(format_args!(
                            "HOST ACPI EC activation refused: {error:?}\n"
                        )),
                    }
                    if let Some(gpe) = binding.device().gpe
                        && let Err(error) = self.session.flag_gpe(gpe, true, &EC_EVENT)
                    {
                        output::arguments(format_args!("HOST ACPI EC GPE refused: {error:?}\n"));
                    }
                }
                if let Err(error) = self.session.flag_fixed_event(
                    stela_drivers::platform::acpi::EVENT_POWER_BUTTON,
                    &POWER_BUTTON,
                ) {
                    output::arguments(format_args!("HOST ACPI power button refused: {error:?}\n"));
                }
                self.attach_power_buttons();
                match self.session.notify_all(|_, value| {
                    POWER_CHANGED.store(true, Ordering::Release);
                    if stela_drivers::probe::backlight::switches(value) {
                        BRIGHTNESS_SEEN.store(value, Ordering::Release);
                    }
                }) {
                    Ok(notification) => *self.notification.borrow_mut() = Some(notification),
                    Err(error) => {
                        output::arguments(format_args!("HOST ACPI notify refused: {error:?}\n"))
                    }
                }
                if let Err(error) = self.session.update_all_gpes() {
                    output::arguments(format_args!("HOST ACPI GPE update refused: {error:?}\n"));
                }
                output::arguments(format_args!(
                    "HOST ACPI hardware active: routed SCI and deferred events\n"
                ));
            }
            Err(error) => output::arguments(format_args!(
                "UNSUPPORTED ACPI hardware activation: {error:?}\n"
            )),
        }
    }

    /// `call` with the loaded namespace, in a bounded firmware call
    /// ([`bounded`]) on the work owner's continuation; `None`, reported,
    /// when it did not finish or could not run. `writes` admits AML's PCI
    /// configuration writes through the native owner for this call alone,
    /// which it allows only before the census (`Source::write_before_census`).
    pub(super) fn firmware<T: 'static>(
        &'static self,
        what: &'static str,
        then: &'static str,
        writes: bool,
        call: impl FnOnce(&'static Session) -> T + 'static,
    ) -> Option<T> {
        // SAFETY: this permanent provider is held by the leaked Session.
        let provider = unsafe { &*self.provider };
        let timeout = u64::from(AML_BOUND_MS) * 1000 + 1_000_000;
        match provider.executor.call_owned(timeout, move || {
            bounded(what, then, || {
                // SAFETY: as above.
                let provider = unsafe { &*self.provider };
                provider.config_writes.set(writes);
                let value = call(&self.session);
                provider.config_writes.set(false);
                value
            })
        }) {
            Ok((value, true)) => Some(value),
            Ok((_, false)) => None,
            Err(error) => {
                output::arguments(format_args!(
                    "UNSUPPORTED ACPI {what}: continuation unavailable: {error}; {then}\n"
                ));
                None
            }
        }
    }

    /// What `\_S5` evaluates to, for the load's line.
    fn describe_s5(session: &Session) -> String {
        match session
            .handle("\\_S5")
            .and_then(|s5| s5.evaluate(None, &[]))
        {
            Ok(Some(Value::Package(values))) => {
                let values: Vec<_> = values
                    .iter()
                    .map(|value| match value {
                        Value::Integer(value) => alloc::format!("{value:#x}"),
                        _ => String::from("?"),
                    })
                    .collect();
                alloc::format!("\\_S5 {}", values.join(","))
            }
            Ok(_) => String::from("\\_S5 is not a package"),
            Err(error) => alloc::format!("no \\_S5 (ACPICA status {:#x})", error.0),
        }
    }

    pub(super) fn embedded_controller(
        &self,
    ) -> Result<
        Option<stela_drivers::platform::ec::capability::Installed<'static>>,
        stela_drivers::probe::ServiceError,
    > {
        if let Some(installed) = self.installed_ec.borrow().clone() {
            return Ok(Some(installed));
        }
        if self.ec.borrow().is_some()
            || self.ec_failed.load(Ordering::Acquire)
            || !self.hardware_active()
        {
            return Err(stela_drivers::probe::ServiceError::Unavailable);
        }
        Ok(None)
    }
    /// `bytes` of firmware RAM at `physical` through the mapping AML's
    /// SystemMemory regions reach it by, kept for the program as theirs are.
    pub(super) fn firmware_memory(&self, physical: u64, bytes: u64) -> Option<NonNull<u8>> {
        // SAFETY: this permanent provider is held by the leaked Session.
        let provider = unsafe { &*self.provider };
        provider.reach(physical, bytes).and_then(NonNull::new)
    }
    /// Keep the power devices; the lid's STATUS notifications are counted
    /// for [`Self::service_lid`], as Linux's `acpi_lid_notify` takes them.
    /// The reading the lid starts with counts for nothing
    /// ([`stela_boot_core::lid_panel`]). One line for the lid.
    ///
    /// The devices' start returns here on the dispatcher's stack, outside
    /// the work owner's continuation, where ACPICA must not run: its
    /// namespace guard and mutexes take the continuation's identity
    /// ([`thread_id`]), which stops the boot anywhere else. So the lid's
    /// path and its notify handler are a bounded firmware call
    /// ([`Self::firmware`]), as the brightness keys' attachment is; what is
    /// kept and published reads only what the probe already read.
    pub(super) fn retain_power(&'static self, power: stela_drivers::probe::Power) {
        let lid = power.lid.as_ref().map(|lid| lid.handle());
        super::battery::publish(&power);
        *self.power.borrow_mut() = power;
        if let Some(lid) = lid {
            self.firmware(
                "lid notify handler",
                "nothing follows the lid",
                false,
                move |_| self.follow_lid(lid),
            );
        }
    }
    /// The lid's notify handler and its line, in the firmware call
    /// [`Self::retain_power`] makes.
    fn follow_lid(&'static self, lid: stela_drivers::platform::acpi::Handle<'static>) {
        use stela_drivers::platform::lid::NOTIFY_STATUS;
        let path = lid.path().unwrap_or_else(|_| String::from("PNP0C0D"));
        let follows = if super::lid::method() {
            "--lid method: a close it notifies darkens a display on built-in panels alone"
        } else {
            "--lid ignore: nothing follows it"
        };
        match lid.notify(|value| {
            if value == NOTIFY_STATUS {
                LID_NOTIFIED.fetch_add(1, Ordering::AcqRel);
            }
        }) {
            Ok(notification) => {
                output::arguments(format_args!("HOST ACPI lid {path}: {follows}\n"));
                *self.lid_notification.borrow_mut() = Some(notification);
            }
            Err(error) => output::arguments(format_args!(
                "HOST ACPI lid {path}: notify handler refused: {error:?}; nothing follows it\n"
            )),
        }
    }
    /// Read the batteries' state (`_BST`) and the AC adapter (`_PSR`) again
    /// at the next poll, as Linux polls them, while hardware mode runs; a
    /// battery's information and the lid wait for their notifications.
    pub(super) fn refresh_power(&self) {
        if self.hardware_active() {
            POWER_POLL.store(true, Ordering::Release);
        }
    }
    pub(super) fn hardware_active(&self) -> bool {
        self.hardware.load(Ordering::Acquire)
    }
    /// What the power button did since the last call: whether its fixed
    /// event fired, and how many notifications its control-method buttons
    /// had, which the power control debounces (`engine::power`).
    pub(super) fn take_power_button(&self) -> (bool, u32) {
        (
            POWER_BUTTON.swap(false, Ordering::AcqRel),
            BUTTON_NOTIFIED.swap(0, Ordering::AcqRel),
        )
    }

    /// Linux's `acpi_button` on each control-method power button (PNP0C0C),
    /// whose presses a firmware with PWR_BUTTON set in its FADT sends as
    /// notifications rather than the fixed event: each counts, and the
    /// power control takes them as presses (`engine::power`). One line for
    /// each button.
    fn attach_power_buttons(&'static self) {
        use stela_drivers::platform::button;
        let found = match button::attach_power_buttons(&self.session, &BUTTON_NOTIFIED) {
            Ok(found) => found,
            Err(error) => {
                output::arguments(format_args!(
                    "HOST ACPI power button search refused: {error:?}\n"
                ));
                return;
            }
        };
        for (path, error) in &found.refused {
            output::arguments(format_args!(
                "HOST ACPI power button {path}: notify handler refused: {error:?}\n"
            ));
        }
        for button in &found.buttons {
            output::arguments(format_args!(
                "HOST ACPI power button {}: control method, its presses reach the guest\n",
                button.path
            ));
        }
        *self.buttons.borrow_mut() = found.buttons;
    }

    /// Whether any deferred ACPI, SCI, EC, power, lid, brightness or ASUS WMI
    /// work is currently pending. Checked lock-free on the BSP guest loop so
    /// idle boundaries never acquire [`super::storage::RestoreRoot`].
    fn needs_poll(&self, provider: &Provider) -> bool {
        if provider.queued.load(Ordering::Acquire)
            || POWER_CHANGED.load(Ordering::Acquire)
            || POWER_POLL.load(Ordering::Acquire)
            || EC_EVENT.load(Ordering::Acquire)
            || self.ec_pending.get()
            || LID_NOTIFIED.load(Ordering::Acquire) != 0
            || BRIGHTNESS_SEEN.load(Ordering::Acquire) != 0
            || BRIGHTNESS.iter().any(|b| b.load(Ordering::Acquire) != 0)
            || ASUS_EVENTS.load(Ordering::Acquire) != 0
        {
            return true;
        }
        if !self.hardware_active() {
            return false;
        }
        provider.needs_rearm.get()
            || provider
                .sci_governor
                .get()
                .is_some_and(|governor| governor.polled())
            || provider
                .sci
                .try_borrow()
                .ok()
                .is_some_and(|sci| sci.as_ref().is_some_and(|armed| armed.interrupted()))
    }

    pub(super) fn poll(&'static self) {
        // SAFETY: this permanent provider is held by the leaked Session.
        let provider = unsafe { &*self.provider };
        // These observations do not borrow AML/provider mutable state while an
        // uncertain continuation might remain held in quarantine.
        if self.deferred_failed.load(Ordering::Acquire) || !self.needs_poll(provider) {
            return;
        }
        // Do not spin waiting for `Domain::Shared` if another core currently
        // holds it (e.g. `host_core` pumping the GPU): try again on the next
        // guest boundary.
        if super::storage::host_drivers_taken() {
            return;
        }
        if let Err(error) = provider
            .executor
            .call_owned(5_000_000, move || self.poll_entered())
            && !self.deferred_failed.swap(true, Ordering::AcqRel)
        {
            output::arguments(format_args!(
                "UNSUPPORTED ACPI deferred work admission failed: {error}\n"
            ));
        }
    }
    fn poll_entered(&self) {
        bounded(
            "deferred work",
            "the work it left waits for the next poll",
            || self.poll_bounded(),
        );
    }
    fn poll_bounded(&self) {
        // SAFETY: the work dispatcher owns the loader root and driver
        // exclusion across this continuation; the Session keeps the provider.
        let provider = unsafe { &*self.provider };
        provider.dispatch_sci(true);
        if EC_EVENT.swap(false, Ordering::AcqRel) || self.ec_pending.get() {
            let bindings = self.ec.borrow();
            if let Some(binding) = bindings.as_ref() {
                self.service_ec(binding);
            }
        }
        // A notification's full refresh reads the state a timed one would.
        let timed = POWER_POLL.swap(false, Ordering::AcqRel);
        if POWER_CHANGED.swap(false, Ordering::AcqRel) {
            let mut power = self.power.borrow_mut();
            for battery in &mut power.batteries {
                if let Err(error) = battery.refresh() {
                    output::arguments(format_args!(
                        "HOST ACPI battery refresh failed: {error:?}\n"
                    ));
                }
            }
            if let Some(ac) = &mut power.ac
                && let Err(error) = ac.refresh()
            {
                output::arguments(format_args!("HOST ACPI AC refresh failed: {error:?}\n"));
            }
            if let Some(lid) = &mut power.lid
                && let Err(error) = lid.refresh()
            {
                output::arguments(format_args!("HOST ACPI lid refresh failed: {error:?}\n"));
            }
            super::battery::publish(&power);
        } else if timed {
            let started = host::fresh_counter();
            let mut power = self.power.borrow_mut();
            let mut failure = None;
            for battery in &mut power.batteries {
                if let Err(error) = battery.refresh_state() {
                    failure = Some(alloc::format!("battery {error:?}"));
                }
            }
            if let Some(ac) = &mut power.ac
                && let Err(error) = ac.refresh()
            {
                failure = Some(alloc::format!("AC adapter {error:?}"));
            }
            super::battery::publish(&power);
            drop(power);
            let took = host::fresh_counter().wrapping_sub(started) / (host::COUNTER_HZ / 1000);
            super::battery::polled(failure.as_deref(), took);
        }
        self.service_ucsi();
        // SAFETY: run Notify/_Q work queued by device methods on the BSP.
        // A budgeted EC continuation owns only its disabled GPE, allowing
        // unrelated fixed events and GPEs to keep making SCI progress.
        if unsafe { drain_work(self.provider.cast_mut().cast()) } != AE_OK {
            output::fatal("ACPI deferred work completion failed");
        }
        self.service_lid();
        self.service_brightness();
        self.service_asus_wmi();
    }

    /// Linux's `acpi_ec_event_handler`: the EC's queries (`QR_EC`), each
    /// one's `_Qxx` run, until the EC has none, then its GPE resumed, which
    /// its raw handler disabled ([`Session::flag_gpe`]). At most 32 a poll
    /// and `QUERIES_PER_WINDOW` a second; past `EC_FAILURES` failed
    /// transactions in a row its events stop, its GPE left disabled
    /// ([`EcGovernor`]). Each query number is named once.
    fn service_ec(&self, binding: &stela_drivers::platform::ec::binding::Binding<'static>) {
        // SAFETY: this permanent provider is held by the leaked Session.
        let now = unsafe { &*self.provider }.now_ms();
        let mut governor = self.ec_governor.borrow_mut();
        let governor = governor.get_or_insert_with(|| EcGovernor::new(now));
        self.ec_pending.set(true);
        for _ in 0..32 {
            match governor.admit(now) {
                Admit::Take => {}
                Admit::Wait { first } => {
                    if first {
                        output::arguments(format_args!(
                            "HOST ACPI EC query budget: {} queries in the last second; the rest \
                             wait for the next\n",
                            hardware_mode::QUERIES_PER_WINDOW
                        ));
                    }
                    return;
                }
                Admit::Stopped => {
                    self.ec_pending.set(false);
                    return;
                }
            }
            match binding.poll_query() {
                Ok(Some(event)) => {
                    governor.succeeded();
                    let number = event.value();
                    let result = event.dispatch();
                    if governor.first(number) {
                        match result {
                            Ok(()) => output::arguments(format_args!(
                                "HOST ACPI EC query {number:#04x}: _Q{number:02X} ran (each \
                                 query is named once)\n"
                            )),
                            Err(error) => output::arguments(format_args!(
                                "HOST ACPI EC query {number:#04x} failed: {error:?} (each query \
                                 is named once)\n"
                            )),
                        }
                    }
                }
                Ok(None) => {
                    governor.succeeded();
                    if let Some(number) = binding.device().gpe {
                        let gpe = stela_drivers::platform::acpi::Gpe {
                            block: None,
                            number,
                        };
                        if let Err(error) = self.session.enable_gpe(gpe) {
                            output::arguments(format_args!(
                                "HOST ACPI EC GPE resume failed: {error:?}\n"
                            ));
                            return;
                        }
                    }
                    self.ec_pending.set(false);
                    return;
                }
                Err(error) => {
                    output::arguments(format_args!("HOST ACPI EC transaction failed: {error:?}\n"));
                    if governor.failed() {
                        output::arguments(format_args!(
                            "HOST ACPI EC events stopped after {} failed transactions in a row: \
                             its GPE stays disabled, so the battery, lid and hotkey events that \
                             come as EC queries no longer arrive\n",
                            hardware_mode::EC_FAILURES
                        ));
                        self.ec_pending.set(false);
                    }
                    return;
                }
            }
        }
    }

    /// The lid's STATUS notifications since the last poll: `_LID` read
    /// anew, as Linux's `acpi_lid_notify` reads it, and with `--lid method`
    /// the lid's request moved ([`super::lid::notified`]). One line for
    /// each poll that saw some, so a boot's log counts them.
    fn service_lid(&self) {
        let notified = LID_NOTIFIED.swap(0, Ordering::AcqRel);
        if notified == 0 {
            return;
        }
        let mut power = self.power.borrow_mut();
        let Some(lid) = &mut power.lid else {
            return;
        };
        let path = lid.path().unwrap_or_else(|_| String::from("PNP0C0D"));
        let open = match lid.refresh() {
            Ok(open) => open,
            Err(error) => {
                output::arguments(format_args!(
                    "HOST ACPI lid {path}: {notified} notification(s), _LID failed: {error:?}\n"
                ));
                return;
            }
        };
        let what = match super::lid::notified(open) {
            _ if !super::lid::method() => "--lid ignore, so nothing follows",
            Some(true) => "a display on built-in panels alone goes dark",
            Some(false) => "the panel lights again",
            None => "nothing changes",
        };
        output::arguments(format_args!(
            "HOST ACPI lid {path}: {notified} notification(s), _LID reads {}: {what}\n",
            if open { "open" } else { "closed" }
        ));
    }

    /// Linux's asus-wmi on an ASUS laptop's WMI device that has the
    /// notebook events: a notify handler on its event block first, and only
    /// once it is in, INIT, after which the firmware reports its Fn hotkeys
    /// as events into a queue that each one must be read from; then the
    /// keyboard backlight read and set to that level, as asus-wmi registers
    /// its LED. The events are taken at the next poll
    /// ([`Self::service_asus_wmi`]). One line, where the device exists.
    fn attach_asus_wmi(&'static self) {
        use stela_drivers::platform::asus_wmi::AsusWmi;
        let mut wmi = match AsusWmi::find(&self.session) {
            Ok(Some(wmi)) => wmi,
            Ok(None) => return,
            Err(error) => {
                output::arguments(format_args!("HOST ASUS WMI search refused: {error:?}\n"));
                return;
            }
        };
        let notify = wmi.notify;
        let notification = match wmi.handle().notify(move |value| {
            if value == notify {
                ASUS_EVENTS.fetch_add(1, Ordering::AcqRel);
            }
        }) {
            Ok(notification) => notification,
            Err(error) => {
                // INIT would route the hotkeys into a queue nothing reads.
                output::arguments(format_args!(
                    "HOST ASUS WMI {}: notify handler refused: {error:?}; INIT is not called, \
                     so its hotkeys stay as the firmware has them\n",
                    wmi.path
                ));
                return;
            }
        };
        let init = match wmi.init() {
            Ok(answer) => alloc::format!("INIT answered {answer:#x}"),
            Err(error) => alloc::format!("INIT refused ({error:?})"),
        };
        let keyboard = match wmi.read_keyboard() {
            Ok(Some(level)) => match wmi.set_keyboard(i32::from(level)) {
                Ok(_) => alloc::format!(
                    "keyboard backlight at {level} of {}, which its keys step",
                    stela_drivers::platform::asus_wmi::KEYBOARD_MAX
                ),
                Err(error) => alloc::format!("keyboard backlight refused its level: {error:?}"),
            },
            Ok(None) => String::from("no keyboard backlight"),
            Err(error) => alloc::format!("keyboard backlight unreadable: {error:?}"),
        };
        output::arguments(format_args!(
            "HOST ASUS WMI {} ({}): {init}, {keyboard}, its hotkey events are taken\n",
            wmi.path,
            wmi.method()
        ));
        *self.asus.borrow_mut() = Some((wmi, notification));
    }

    /// Set an ASUS laptop's firmware thermal policy to `mode` before macOS
    /// starts, as Linux's asus-wmi sets `throttle_thermal_policy` at probe,
    /// so macOS runs in it whatever Windows last chose, in its own bounded
    /// firmware call, with or without hardware mode: DSTS finds the policy
    /// device, DEVS sets it. One line saying what it was, what was set and
    /// what the firmware then reads, or why it was skipped; nothing on a PC
    /// without an ASUS notebook's WMI device. The package power limits the
    /// device names are read alongside, and only read. A failure is
    /// reported and the boot goes on.
    pub(super) fn set_asus_thermal_policy(&'static self, mode: stela_boot_core::options::AsusMode) {
        use stela_boot_core::options::AsusMode;
        use stela_drivers::platform::asus_wmi::ThermalMode;
        let wanted = match mode {
            AsusMode::Off => {
                output::arguments(format_args!(
                    "ASUS thermal policy: skipped, --asus-mode off leaves it as the firmware has it\n"
                ));
                return;
            }
            AsusMode::Performance => ThermalMode::Default,
            AsusMode::Turbo => ThermalMode::Overboost,
            AsusMode::Silent => ThermalMode::Silent,
        };
        self.firmware(
            "ASUS thermal policy",
            "the policy is left as the firmware has it",
            false,
            move |session| Self::asus_thermal_policy_entered(session, wanted),
        );
    }
    /// [`Self::set_asus_thermal_policy`]'s firmware call.
    fn asus_thermal_policy_entered(
        session: &'static Session,
        wanted: stela_drivers::platform::asus_wmi::ThermalMode,
    ) {
        use stela_drivers::platform::asus_wmi::{AsusWmi, ThermalMode, mode_in_effect};
        let wmi = match AsusWmi::find(session) {
            Ok(Some(wmi)) => wmi,
            // Not an ASUS notebook: nothing to say.
            Ok(None) => return,
            Err(error) => {
                output::arguments(format_args!(
                    "ASUS thermal policy: skipped, the WMI device search was refused ({error:?})\n"
                ));
                return;
            }
        };
        let policy = match wmi.thermal_policy() {
            Ok(Some(policy)) => policy,
            Ok(None) => {
                output::arguments(format_args!(
                    "ASUS thermal policy: skipped, {} has no thermal policy device\n",
                    wmi.path
                ));
                return;
            }
            Err(error) => {
                output::arguments(format_args!(
                    "ASUS thermal policy: skipped, {} DSTS refused ({error:?})\n",
                    wmi.path
                ));
                return;
            }
        };
        // DSTS of the policy answers no mode on the FA608PP (a constant
        // 0x00010003), and asus-wmi reads none; its firmware keeps the mode
        // in effect in its EC's FTBL, which DEVS of 0x00120075 writes. Read
        // where that field exists and reads, as AML reads it.
        let mode = || -> String {
            match mode_in_effect(session, &policy) {
                Some(value) => match u32::try_from(value)
                    .ok()
                    .and_then(|value| ThermalMode::from_value(value, policy.device))
                {
                    Some(mode) => String::from(mode.name()),
                    None => alloc::format!("FTBL {value:#x}"),
                },
                None => String::from("unknown"),
            }
        };
        let was = mode();
        let line = match wmi.set_thermal_policy(&policy, wanted) {
            Ok(value) => alloc::format!(
                "ASUS thermal policy: was {was}, set {} ({:#x} = {value} by DEVS, DSTS {:#x}), \
                 the firmware reads {}\n",
                wanted.name(),
                policy.device,
                policy.status,
                mode()
            ),
            Err(error) => alloc::format!(
                "ASUS thermal policy: was {was}, set {} refused ({:#x} by DEVS: {error:?}), the \
                 boot goes on\n",
                wanted.name(),
                policy.device
            ),
        };
        output::arguments(format_args!("{line}"));
        let limits = wmi.power_limits();
        let limits: Vec<String> = limits
            .into_iter()
            .map(|(name, status)| match status {
                Ok(status) => alloc::format!("{name}={:#x}", status & 0xffff),
                Err(error) => alloc::format!("{name}=refused({error:?})"),
            })
            .collect();
        output::arguments(format_args!(
            "HOST POWER LIMITS asus-wmi {}: {} (DSTS's value bits, read only; 0 is a limit the \
             firmware does not report)\n",
            wmi.path,
            if limits.is_empty() {
                String::from("none present")
            } else {
                limits.join(" ")
            }
        ));
    }

    /// The ASUS WMI events since the last poll: at any notification, the
    /// firmware's whole queue read through `_WED` until it is empty
    /// ([`stela_drivers::platform::asus_wmi::AsusWmi::drain`]), past a read
    /// that fails, so a missed notification leaves no event behind to fill
    /// it: a keyboard backlight key steps it, and any other code is named.
    fn service_asus_wmi(&self) {
        let notified = ASUS_EVENTS.swap(0, Ordering::AcqRel);
        if notified == 0 {
            return;
        }
        let mut kept = self.asus.borrow_mut();
        let Some((wmi, _)) = kept.as_mut() else {
            return;
        };
        for read in wmi.drain(ASUS_DRAIN) {
            let code = match read {
                Ok(code) => code,
                Err(error) => {
                    output::arguments(format_args!("HOST ASUS WMI event unreadable: {error:?}\n"));
                    continue;
                }
            };
            match wmi.keyboard_key(code) {
                Ok(Some((from, to))) => output::arguments(format_args!(
                    "HOST ASUS WMI keyboard backlight {from} -> {to} of {} (event {code:#x})\n",
                    stela_drivers::platform::asus_wmi::KEYBOARD_MAX
                )),
                Ok(None) => {
                    output::arguments(format_args!("HOST ASUS WMI event {code:#x}: not taken\n"))
                }
                Err(error) => output::arguments(format_args!(
                    "HOST ASUS WMI keyboard backlight refused (event {code:#x}): {error:?}\n"
                )),
            }
        }
    }

    /// With `--brightness-keys`, Linux's ACPI video driver on each display
    /// output device with `_BCL` and `_BCM` its video bus's `_DOD` lists
    /// ([`stela_drivers::probe::backlight::controls`]): its level set as at
    /// registration, the level a press without `_BQC` starts from, and its
    /// brightness notifications, which a laptop's brightness keys send,
    /// stepping it ([`Self::service_brightness`]). Linux does this only
    /// where ACPI video owns the backlight, which Stela cannot tell, so it
    /// is asked for. One line for each device, or one saying none was found.
    fn attach_backlights(&'static self) {
        use stela_drivers::probe::backlight;
        if !BRIGHTNESS_KEYS.load(Ordering::Acquire) {
            return;
        }
        let found = match backlight::controls(&self.session) {
            Ok(found) => found,
            Err(error) => {
                output::arguments(format_args!(
                    "HOST ACPI backlight search refused: {error:?}\n"
                ));
                return;
            }
        };
        for path in &found.unlisted {
            output::arguments(format_args!(
                "HOST ACPI backlight {path}: _BCL lists no levels, so the brightness keys leave it\n"
            ));
        }
        for path in &found.undeclared {
            output::arguments(format_args!(
                "HOST ACPI backlight {path}: its video bus's _DOD does not list it (or it has no \
                 _ADR), so the brightness keys leave it\n"
            ));
        }
        if found.controls.is_empty() {
            output::arguments(format_args!(
                "HOST ACPI backlight: no display output in _DOD has _BCL and _BCM, so the \
                 brightness keys find no backlight control\n"
            ));
        }
        let mut kept = self.backlights.borrow_mut();
        for (index, mut control) in found.controls.into_iter().enumerate() {
            if index >= BACKLIGHTS {
                output::arguments(format_args!(
                    "HOST ACPI backlight {}: past the first {BACKLIGHTS} outputs, its brightness \
                     keys are not followed\n",
                    control.path
                ));
                continue;
            }
            let set = match control.initialize() {
                Ok(set) => alloc::format!("set to {} of {}", set.level, set.max),
                Err(error) => alloc::format!(
                    "_BCM refused its first level (status {:#x}), so a first press starts from \
                     the middle",
                    error.0
                ),
            };
            let path = &control.path;
            if index >= BACKLIGHTS {
                output::arguments(format_args!(
                    "HOST ACPI backlight {path}: past the first {BACKLIGHTS} outputs, its brightness \
                     keys are not followed\n"
                ));
                continue;
            }
            let notified = control.handle().notify(move |value| {
                if backlight::switches(value) {
                    BRIGHTNESS[index].store(value, Ordering::Release);
                }
            });
            match notified {
                Ok(notification) => {
                    output::arguments(format_args!(
                        "HOST ACPI backlight {path}: _BCL lists {} levels up to {}, {set}, and \
                         the brightness keys step it through _BCM\n",
                        control.levels.count(),
                        control.levels.max()
                    ));
                    kept.push((control, notification));
                }
                Err(error) => output::arguments(format_args!(
                    "HOST ACPI backlight {path}: notify handler refused: {error:?}\n"
                )),
            }
        }
    }

    /// Each followed output's brightness notification since the last poll:
    /// its next level set through its `_BCM`, with a line. A brightness
    /// notification no followed output took is named too.
    fn service_brightness(&self) {
        use stela_drivers::probe::backlight;
        let what = |event| match event {
            backlight::NOTIFY_INC => "up",
            backlight::NOTIFY_DEC => "down",
            backlight::NOTIFY_CYCLE => "cycled",
            backlight::NOTIFY_ZERO => "to zero",
            _ => "off",
        };
        let seen = BRIGHTNESS_SEEN.swap(0, Ordering::AcqRel);
        if !BRIGHTNESS_KEYS.load(Ordering::Acquire) {
            return;
        }
        let mut taken = false;
        for (index, (control, _)) in self.backlights.borrow_mut().iter_mut().enumerate() {
            let event = BRIGHTNESS[index].swap(0, Ordering::AcqRel);
            if event == 0 {
                continue;
            }
            taken = true;
            let switched = control.switch(event);
            let path = &control.path;
            match switched {
                Ok(switched) => output::arguments(format_args!(
                    "HOST ACPI backlight {path}: brightness {} {} -> {} of {} through _BCM ({})\n",
                    what(event),
                    switched.from,
                    switched.to,
                    switched.max,
                    if switched.read {
                        "from the level _BQC read"
                    } else {
                        "from the level last set"
                    }
                )),
                Err(error) => output::arguments(format_args!(
                    "HOST ACPI backlight {path}: brightness {} refused by _BCM (status {:#x})\n",
                    what(event),
                    error.0
                )),
            }
        }
        if seen != 0 && !taken {
            output::arguments(format_args!(
                "HOST ACPI brightness {}: no display output with _BCL and _BCM took it, so no \
                 backlight control found\n",
                what(seen)
            ));
        }
    }

    /// Linux `ucsi_acpi_notify`'s work: each running UCSI manager whose
    /// Notify arrived reads and acknowledges its connector changes. A manager
    /// that faults is reported once and left stopped.
    fn service_ucsi(&self) {
        let mut power = self.power.borrow_mut();
        for (index, ucsi) in power.ucsi.iter_mut().enumerate() {
            if ucsi.state() != ucsi::State::Running || !ucsi.needs_service() {
                continue;
            }
            match ucsi.service(UCSI_SERVICE_BUDGET) {
                Ok(report) => {
                    for change in &report.changes {
                        output::arguments(format_args!(
                            "HOST USB-C {index} connector {}: {}\n",
                            change.number.get(),
                            change.status
                        ));
                    }
                    if let Some(error) = report.error {
                        output::arguments(format_args!(
                            "HOST USB-C {index} connector change failed: {error:?}\n"
                        ));
                    }
                }
                Err(error) => output::arguments(format_args!(
                    "HOST USB-C {index} manager stopped: {error:?}\n"
                )),
            }
        }
    }

    /// The firmware's processor idle declaration, once the processors are
    /// told `capabilities`; `None`, reported, when AML refuses it.
    pub(super) fn processor_idle(
        &'static self,
        capabilities: u32,
    ) -> Option<stela_drivers::platform::acpi::processor::Declaration> {
        // SAFETY: this permanent provider is held by the leaked Session.
        let provider = unsafe { &*self.provider };
        match provider.executor.call_owned(5_000_000, move || {
            bounded("processor idle declaration", "processors halt", || {
                self.session.processor_idle(capabilities)
            })
        }) {
            Ok((Ok(declaration), true)) => Some(declaration),
            Ok((Ok(_), false)) => None,
            Ok((Err(error), _)) => {
                output::arguments(format_args!(
                    "UNSUPPORTED ACPI processor idle declaration: ACPICA status {:#x}\n",
                    error.0
                ));
                None
            }
            Err(error) => {
                output::arguments(format_args!(
                    "ACPI processor idle continuation unavailable: {error}\n"
                ));
                None
            }
        }
    }

    /// The loaded namespace. Its calls run in the loader root
    /// ([`super::storage::RestoreRoot`]), as the host drivers do.
    pub fn session(&'static self) -> &'static Session {
        &self.session
    }

    /// Linux's `acpi_power_off_prepare`: S5's SLP_TYPa and SLP_TYPb as the
    /// firmware's `\_S5` evaluates, after `\_PTS(5)` and `\_SST`; `None`
    /// without S5. A failed `\_PTS` is reported, and S5 follows all the same.
    pub fn prepare_soft_off(&'static self) -> Option<(u8, u8)> {
        // SAFETY: this permanent provider is held by the leaked Session.
        let provider = unsafe { &*self.provider };
        match provider
            .executor
            .call_owned(5_000_000, move || self.prepare_soft_off_entered())
        {
            Ok(types) => types,
            Err(error) => {
                output::arguments(format_args!(
                    "POWER firmware continuation unavailable: {error}\n"
                ));
                None
            }
        }
    }
    fn prepare_soft_off_entered(&self) -> Option<(u8, u8)> {
        bounded("S5 preparation", "S5 follows", || {
            self.prepare_soft_off_bounded()
        })
        .0
    }
    fn prepare_soft_off_bounded(&self) -> Option<(u8, u8)> {
        let types = match self.session.sleep_types(5) {
            Ok(types) => types,
            Err(error) => {
                output::arguments(format_args!(
                    "POWER the firmware's AML has no S5: ACPICA status {:#x}\n",
                    error.0
                ));
                return None;
            }
        };
        match self.session.prepare_sleep(5) {
            Ok(()) => output::arguments(format_args!(
                "POWER the firmware prepared S5: SLP_TYPa={:#x} SLP_TYPb={:#x}\n",
                types.0, types.1
            )),
            Err(error) => output::arguments(format_args!(
                "POWER \\_PTS(5) failed: ACPICA status {:#x}\n",
                error.0
            )),
        }
        Some(types)
    }
}
