//! The mount's native page source over its heap, and the Linux page catalog
//! bound to it. The source itself is `stela_boot_core::native_memory`.
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};
use stela_boot_core::native_memory::{NativeMemory, PAGE, Registration};
use stela_drivers::bus::dma::memory::{
    CacheAttribute, MemoryError, PageGeometry, PageSource, PinnedPages,
};

pub(crate) mod cache;

pub static SOURCE: NativeMemory = NativeMemory::new(&crate::ALLOCATOR, cache::verify_writeback);

static AMD_TABLE_HEAP: stela_boot_core::heap::Heap = stela_boot_core::heap::Heap::new();
pub(crate) static AMD_TABLES: NativeMemory =
    NativeMemory::new(&AMD_TABLE_HEAP, cache::verify_writeback);

/// Register the separate low physical memory reserved for AMD-Vi tables.
///
/// # Safety
/// The loader's exclusive LOADER_DATA reservation remains mapped in every
/// native root, outside the guest and driver DMA ranges. Call once on the BSP
/// before remapper startup.
pub(crate) unsafe fn initialize_amd_tables(
    region: crate::handoff::Region,
) -> Result<(), MemoryError> {
    if region.bytes == 0 {
        return Ok(());
    }
    let bytes = usize::try_from(region.bytes).map_err(|_| MemoryError::InvalidSize)?;
    let cpu = crate::layout::physical(region.physical);
    // SAFETY: the caller retains this reservation and all shared mappings.
    unsafe { qualify_reserved_writeback(cpu, region.physical, bytes) }?;
    // SAFETY: unused firmware-owned RAM; the AMD table heap is its only owner.
    unsafe {
        AMD_TABLE_HEAP.initialize(cpu as *mut u8, bytes);
        AMD_TABLES.initialize(
            cpu as usize,
            region.physical,
            bytes,
            crate::layout::physical(0),
        );
    }
    Ok(())
}

static LOW_DMA_HEAP: stela_boot_core::heap::Heap = stela_boot_core::heap::Heap::new();
/// Exclusive firmware RAM below 4 GiB for devices that reach only 32-bit
/// addresses when no IOMMU translates for them: the heap is one firmware
/// allocation of several GiB, which the firmware may place wholly above
/// 4 GiB, where `allocate_below` then finds nothing (an RTL8852CE's rings on
/// an AMD laptop with AMD-Vi left off). Linux's DMA API takes such pages from
/// ZONE_DMA32 or bounces them; this pool is that zone.
static LOW_DMA: NativeMemory = NativeMemory::new(&LOW_DMA_HEAP, cache::verify_writeback);
/// The pool's physical range, `start..end`; both zero while it is absent.
static LOW_DMA_START: AtomicU64 = AtomicU64::new(0);
static LOW_DMA_END: AtomicU64 = AtomicU64::new(0);

/// Pages of the low DMA pool to ask the firmware for, largest first: an
/// RTL8852CE's rings, RX buffers and TX pools take about 1.1 MiB, and the
/// rest leaves room for other 32-bit requesters (HDA, tg3) on a
/// passthrough domain.
const LOW_DMA_PAGES: [usize; 3] = [4096, 2048, 1024];

/// Larger low DMA pool requested only when the PCI census sees an MT7925
/// (`14c3:7925` / `14c3:0717`): it installs 256 WM TX, 128 FWDL TX, 512
/// event RX and 1536 data RX buffers as individual 4 KiB page-aligned
/// allocations (~20 MiB in the heap before in-flight TX buffers and bring-up
/// retries, exceeding 16 MiB), stepping down on tighter firmware maps.
const MT7925_LOW_DMA_PAGES: [usize; 5] = [16384, 8192, 4096, 2048, 1024];

/// Reserve the low DMA pool from the firmware, below 4 GiB, before boot
/// services end. When `mt7925` is true, requests up to 64 MiB first and
/// steps down; otherwise keeps the default 16 MiB ceiling. Without room the
/// pool is absent and a 32-bit request the heap cannot meet fails as before.
pub(crate) fn reserve_low_dma(mt7925: bool) -> crate::handoff::Region {
    use uefi::boot::{self, AllocateType, MemoryType};
    let sizes: &[usize] = if mt7925 {
        &MT7925_LOW_DMA_PAGES
    } else {
        &LOW_DMA_PAGES
    };
    for &pages in sizes {
        if let Ok(allocation) = boot::allocate_pages(
            AllocateType::MaxAddress(u32::MAX.into()),
            MemoryType::LOADER_DATA,
            pages,
        ) {
            let region = crate::handoff::Region {
                physical: allocation.as_ptr() as u64,
                bytes: (pages * PAGE) as u64,
            };
            crate::output::arguments(format_args!(
                "HOST LOW DMA reserved {} KiB below 4 GiB at {:#x}\n",
                region.bytes >> 10,
                region.physical
            ));
            return region;
        }
    }
    crate::output::arguments(format_args!(
        "HOST LOW DMA unavailable: the firmware has no room below 4 GiB\n"
    ));
    crate::handoff::Region::default()
}

/// Register the low DMA pool the loader reserved (`reserve_low_dma`).
///
/// # Safety
/// The loader's exclusive LOADER_DATA reservation remains mapped in every
/// native root and outside guest RAM. Call once on the BSP before any
/// driver starts.
pub(crate) unsafe fn initialize_low_dma(region: crate::handoff::Region) -> Result<(), MemoryError> {
    if region.bytes == 0 {
        return Ok(());
    }
    let bytes = usize::try_from(region.bytes).map_err(|_| MemoryError::InvalidSize)?;
    let end = region
        .physical
        .checked_add(region.bytes)
        .filter(|&end| end <= 1 << 32)
        .ok_or(MemoryError::InvalidSize)?;
    let cpu = crate::layout::physical(region.physical);
    // SAFETY: the caller retains this reservation and all shared mappings.
    unsafe { qualify_reserved_writeback(cpu, region.physical, bytes) }?;
    // SAFETY: unused firmware-owned RAM; the low DMA heap is its only owner.
    unsafe {
        LOW_DMA_HEAP.initialize(cpu as *mut u8, bytes);
        LOW_DMA.initialize(
            cpu as usize,
            region.physical,
            bytes,
            crate::layout::physical(0),
        );
    }
    LOW_DMA_START.store(region.physical, Ordering::Release);
    LOW_DMA_END.store(end, Ordering::Release);
    Ok(())
}

/// The low DMA pool's physical range, which passthrough domains admit; empty
/// while the pool is absent.
pub(crate) fn low_dma_range() -> Option<core::ops::Range<u64>> {
    let end = LOW_DMA_END.load(Ordering::Acquire);
    (end != 0).then(|| LOW_DMA_START.load(Ordering::Acquire)..end)
}

/// The drivers' page source: the heap, and for a request below a physical
/// end that the heap has no room under, the low DMA pool.
pub struct DriverPages;

/// The page source the engine's services hand to drivers.
pub static DRIVER_PAGES: DriverPages = DriverPages;

impl PageSource for DriverPages {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        SOURCE.page_geometry()
    }

    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        SOURCE.allocate(bytes, alignment, attribute)
    }

    fn allocate_below(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
        physical_end_exclusive: u64,
    ) -> Result<PinnedPages, MemoryError> {
        match SOURCE.allocate_below(bytes, alignment, attribute, physical_end_exclusive) {
            Err(MemoryError::OutOfMemory) if low_dma_range().is_some() => {
                LOW_DMA.allocate_below(bytes, alignment, attribute, physical_end_exclusive)
            }
            other => other,
        }
    }
}

/// Register the heap's CPU/physical mapping (`NativeMemory::initialize`).
///
/// # Safety
/// As `NativeMemory::initialize`, for the mount's heap.
pub unsafe fn initialize(cpu: usize, physical: u64, bytes: usize, table_offset: u64) {
    // SAFETY: the caller's contract.
    unsafe { SOURCE.initialize(cpu, physical, bytes, table_offset) }
}

/// The bytes of the heap kept for an integrated GPU's pages, zero for a GPU
/// with memory of its own (`Handoff::gpu_share`).
static GPU_SHARE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The most bytes of pages Linux may hold at once (`Handoff::gpu_pages`).
static GPU_PAGES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The plan holds Linux to [`GPU_PAGES`] (`Handoff::gpu_pages_held`).
static GPU_PAGES_HELD: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The heap region's bytes, the share's among them.
static HEAP_BYTES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Records the integrated GPU's share of the heap the loader planned, the
/// bound on Linux's pages and whether the plan holds Linux to it, and the
/// heap region's bytes. The Metal device of an integrated GPU budgets its
/// allocations by what Linux holds of that bound ([`share_state`]); a
/// discrete GPU's never is (`share::budget`).
pub(crate) fn set_gpu_share(share: u64, pages: u64, held: bool, heap: u64) {
    GPU_SHARE.store(share, core::sync::atomic::Ordering::Relaxed);
    GPU_PAGES.store(pages, core::sync::atomic::Ordering::Relaxed);
    GPU_PAGES_HELD.store(held, core::sync::atomic::Ordering::Relaxed);
    HEAP_BYTES.store(heap, core::sync::atomic::Ordering::Relaxed);
    #[cfg(feature = "nvk")]
    stela_drivers::gpu::metal::device::share::set_probe(share_state);
}

/// The bytes of the integrated GPU's share of RAM the loader planned, zero
/// for a GPU with memory of its own.
pub(crate) fn gpu_share() -> u64 {
    GPU_SHARE.load(core::sync::atomic::Ordering::Relaxed)
}

/// What Linux holds now of the memory an integrated GPU that draws works
/// in, and that memory's size: the page catalog's limit, the share. A plan
/// without one gave the Metal device to a discrete GPU, which did not
/// start, so the integrated GPU draws after all: it then works in the bound
/// the plan figured for Linux's pages, what the heap holds past its own
/// needs, said once, whether or not the plan holds Linux to it. None
/// before the catalog has its limit, or with no bound at all.
#[cfg(feature = "nvk")]
fn share_state() -> Option<stela_drivers::gpu::metal::device::share::ShareState> {
    use core::sync::atomic::{AtomicBool, Ordering};
    static SAID: AtomicBool = AtomicBool::new(false);
    let (held, limit) = stela_linux::pages::held_and_limit();
    let limit = match (limit, GPU_PAGES_HELD.load(Ordering::Relaxed)) {
        (0, true) => return None,
        (0, false) => GPU_PAGES.load(Ordering::Relaxed),
        (limit, _) => limit as u64 * PAGE as u64,
    };
    if limit == 0 {
        return None;
    }
    let state = stela_drivers::gpu::metal::device::share::ShareState {
        held: held as u64 * PAGE as u64,
        limit,
    };
    if GPU_SHARE.load(Ordering::Relaxed) == 0 && !SAID.swap(true, Ordering::Relaxed) {
        crate::output::arguments(format_args!(
            "GPU MEMORY an integrated GPU draws without a share of its own, as the plan gave the \
             Metal device to a discrete GPU that did not start: its allocations are held to the \
             {}M of pages the {}M heap holds past its own needs{}\n",
            state.limit >> 20,
            HEAP_BYTES.load(Ordering::Relaxed) >> 20,
            match GPU_PAGES_HELD.load(Ordering::Relaxed) {
                true => "",
                false => ", by its Metal device alone, as the plan holds Linux to no bound",
            },
        ));
    }
    Some(state)
}

/// Linux's pages once an integrated GPU is to draw in place of a GPU that
/// could not (`host_memory::fallback_pages`), from the bound the plan
/// figured and what Linux holds and is held to now.
pub(crate) fn fallback_pages() -> stela_boot_core::host_memory::FallbackPages {
    let (held, limit) = stela_linux::pages::held_and_limit();
    stela_boot_core::host_memory::fallback_pages(
        fallback_bound(),
        held as u64 * PAGE as u64,
        limit as u64 * PAGE as u64,
    )
}

/// The bytes the plan figured Linux's pages may hold (`Handoff::gpu_pages`),
/// which a fallback holds them to where the plan did not.
pub(crate) fn fallback_bound() -> u64 {
    GPU_PAGES.load(core::sync::atomic::Ordering::Relaxed)
}

/// Linux's pages are held to [`GPU_PAGES`] from now on: a fallback held
/// them where the plan did not.
#[cfg(feature = "nvk")]
pub(crate) fn pages_held() {
    GPU_PAGES_HELD.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// The ordinary pages Linux may hold at once (`Handoff::gpu_pages`): an
/// integrated GPU's share of the heap, or what the heap holds past its own
/// needs, in pages, so that no driver's pages take the heap's own; `None`
/// where the plan holds Linux to no bound (`Handoff::gpu_pages_held`).
pub(crate) fn gpu_page_limit() -> Option<usize> {
    if !GPU_PAGES_HELD.load(core::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let bytes = GPU_PAGES.load(core::sync::atomic::Ordering::Relaxed);
    usize::try_from(bytes / PAGE as u64)
        .ok()
        .filter(|&pages| pages != 0)
}

/// Keeps the same boot heap generation registered through every consumer.
pub(crate) struct HeapPin {
    registration: Registration,
}

impl HeapPin {
    pub(crate) fn registration(&self) -> Registration {
        self.registration
    }
}

impl Drop for HeapPin {
    fn drop(&mut self) {
        SOURCE.release_catalog();
    }
}

/// Retain the currently registered physical heap and prevent a new generation.
///
/// # Safety
/// Caller owns the original heap/root lifetime and excludes registration
/// changes until the pin is acquired. Retiring the last pin is process-only.
pub(crate) unsafe fn pin_heap() -> Result<HeapPin, MemoryError> {
    let registration = SOURCE.registration();
    if registration.generation == 0 || registration.bytes == 0 {
        return Err(MemoryError::Unavailable);
    }
    SOURCE.retain_catalog()?;
    Ok(HeapPin { registration })
}

pub struct LinuxPages {
    heap: HeapPin,
}

// SAFETY: initialize registered the heap and its WB mapping. The catalog
// count prevents retargeting the generation; each allocation goes through the
// zeroed page source and keeps its backing until the last drop. Unsupported
// flags and contexts are refused before any heap or cache work.
unsafe impl stela_linux::pages::Provider for LinuxPages {
    fn validate(&self, request: stela_linux::pages::Request) -> Result<(), MemoryError> {
        // The pinned heap never sleeps or reclaims, so a request that may
        // not block (TTM's GFP_DMA32 page, say) gets what it asked for. Only
        // atomic context, where the heap's lock could be held, is refused.
        if SOURCE.registration().generation != self.heap.registration().generation
            || request.atomic
            || !(request.basic_ram() || request.reclaimable_ram())
        {
            return Err(MemoryError::Unavailable);
        }
        request.bytes().ok_or(MemoryError::InvalidSize)?;
        Ok(())
    }

    fn allocate(&self, request: stela_linux::pages::Request) -> Result<PinnedPages, MemoryError> {
        self.validate(request)?;
        let bytes = request.bytes().ok_or(MemoryError::InvalidSize)?;
        // The same pinned WB heap supplies Linux's unmovable fallback for
        // reclaimable-class requests. Cache accounting keeps the original class.
        SOURCE.allocate(bytes, bytes, CacheAttribute::WriteBack)
    }
}

/// Bind the registered heap to Linux's native page service.
///
/// # Safety
/// Process or deferred-work context excludes migration, root and cache
/// writers and native IRQ reentry for registration, use and retirement. The
/// heap and its mapping stay registered through every pin and any quarantined
/// catalog; the caller retires the catalog before re-registering the heap.
pub unsafe fn linux_pages()
-> Result<stela_linux::pages::Catalog<LinuxPages>, stela_linux::pages::Error> {
    // SAFETY: the caller's contract.
    let (provider, reservation) = unsafe { linux_page_source() }?;
    // SAFETY: the provider holds the catalog count for this generation.
    unsafe { stela_linux::pages::Catalog::register(provider, reservation) }
}

/// The heap generation and extent for one composed catalog. Returning the
/// reservation allocates nothing.
///
/// # Safety
/// As `linux_pages`.
pub(crate) unsafe fn linux_page_source()
-> Result<(LinuxPages, stela_linux::pages::Reservation), stela_linux::pages::Error> {
    use stela_linux::pages::{Error, Reservation};
    // SAFETY: the original catalog source owns this heap/root lifetime.
    let heap = unsafe { pin_heap() }.map_err(|error| match error {
        MemoryError::Unavailable => Error::InvalidReservation,
        _ => Error::OutOfMemory,
    })?;
    let registration = heap.registration();
    let cpu = NonNull::new(registration.cpu as *mut u8).ok_or(Error::InvalidReservation)?;
    // SAFETY: the registration records this mapping of the heap's RAM.
    let reservation =
        unsafe { Reservation::new(registration.physical, cpu, registration.bytes / PAGE)? };
    let provider = LinuxPages { heap };
    Ok((provider, reservation))
}

/// Check that a loader reservation is mapped write-back, with the decoder
/// native pages use. This allocates nothing and adds no alias.
///
/// # Safety
/// The reservation and its CPU mapping last for the boot; root, cache
/// controls and physical ownership do not change during the check.
pub(crate) unsafe fn qualify_reserved_writeback(
    cpu: u64,
    physical: u64,
    bytes: usize,
) -> Result<(), MemoryError> {
    cache::verify_writeback(cpu, physical, bytes, SOURCE.table_offset())
}

/// Exercise the registered mapping and allocator through the Linux page
/// catalog and the page source. Called by the mount's host check.
pub fn verify() -> Result<(), MemoryError> {
    // SAFETY: the host check runs in process context, with root and cache
    // writers excluded.
    let mut catalog = unsafe { linux_pages() }.map_err(|_| MemoryError::Unavailable)?;
    catalog.verify().map_err(|error| {
        crate::output::arguments(format_args!("CHECK Linux page catalog FAIL {error:?}\n"));
        MemoryError::InvalidPageList
    })?;
    catalog.try_retire().map_err(|_| MemoryError::Unavailable)?;
    SOURCE.verify()
}
