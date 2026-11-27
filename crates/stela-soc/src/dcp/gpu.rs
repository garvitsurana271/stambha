//! How far the GPU has got with the work submitted to it, which the display
//! compares with when each swap was submitted.
//!
//! The host's GPU service publishes the serial of the last command buffer
//! submitted and of the last seen complete. A swap submitted after command
//! buffer `n` was submitted may name surfaces that work draws, so a present
//! before `n` completes can show a frame still being drawn.

//!
//! The serials are noted as the service answers the guest's calls, which
//! stop while the guest waits for a frame to be shown. A reader the host
//! sets ([`set_reader`]) gives the newest completed serial the GPU itself
//! wrote, between calls.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static SUBMITTED: AtomicU64 = AtomicU64::new(0);
static COMPLETED: AtomicU64 = AtomicU64::new(0);
/// A `fn() -> Option<u64>` giving the newest serial the GPU completed, or 0.
static READER: AtomicUsize = AtomicUsize::new(0);

/// Read the newest completed serial with `reader` too, as [`completed`]
/// does.
pub fn set_reader(reader: fn() -> Option<u64>) {
    READER.store(reader as usize, Ordering::Release);
}

/// Note the GPU's last submitted and last completed command buffer serials.
pub fn note(submitted: u64, completed: u64) {
    SUBMITTED.store(submitted, Ordering::Release);
    COMPLETED.store(completed, Ordering::Release);
}

/// The serial of the last command buffer submitted.
pub fn submitted() -> u64 {
    SUBMITTED.load(Ordering::Acquire)
}

/// The serial of the last command buffer seen complete.
pub fn completed() -> u64 {
    let noted = COMPLETED.load(Ordering::Acquire);
    let reader = READER.load(Ordering::Acquire);
    if reader == 0 {
        return noted;
    }
    // SAFETY: only `set_reader` stores here, a `fn() -> Option<u64>`.
    let reader: fn() -> Option<u64> = unsafe { core::mem::transmute(reader) };
    reader().map_or(noted, |read| noted.max(read))
}
