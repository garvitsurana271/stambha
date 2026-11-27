//! Journal writes (`stela_formats::journal`) to files in the store's
//! directory, shared by the translation pack and the pipeline store: the
//! targets that carry a journal plan's writes to a file's device extents,
//! queued through the staged partition while the guest runs or completed at
//! once at a stop, and the slot that admits one writer at a time.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
pub(super) use stela_runtime::translation_bulk::{Direct, Queued, Staged};

/// A writer's state, one holder at a time: a step while the guest runs
/// skips while another holds it, the write at a stop waits.
pub(super) struct Held<T> {
    held: AtomicBool,
    value: UnsafeCell<Option<T>>,
}
// SAFETY: `held` admits one holder at a time to `value`; the processors
// share one address space and its allocator, so a writer moves between them
// whole.
unsafe impl<T> Sync for Held<T> {}

impl<T> Held<T> {
    pub(super) const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(None),
        }
    }

    /// Runs `f` on the slot holding it: at once or not at all unless
    /// `wait`.
    pub(super) fn holding<R>(&self, wait: bool, f: impl FnOnce(&mut Option<T>) -> R) -> Option<R> {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            if !wait {
                return None;
            }
            core::hint::spin_loop();
        }
        // SAFETY: `held` is ours until the store below.
        let result = f(unsafe { &mut *self.value.get() });
        self.held.store(false, Ordering::Release);
        Some(result)
    }

    /// Runs `f` on the writer, if there is one and nobody else holds it.
    pub(super) fn try_with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        self.holding(false, |slot| slot.as_mut().map(f)).flatten()
    }

    /// Runs `f` on the writer, if there is one, waiting for its holder.
    pub(super) fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        self.holding(true, |slot| slot.as_mut().map(f)).flatten()
    }
}
