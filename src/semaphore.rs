//! A minimal counting semaphore built on std primitives.
//!
//! std::sync::Semaphore is not stable on this toolchain (unresolved import
//! on rustc 1.91), so here is the ~30-line equivalent: a permit pool guarded
//! by a Mutex + Condvar. Used by main.rs to bound the number of concurrently
//! alive connection threads (→ DESIGN.md bounded concurrency; a NOSY semaphore
//! crate would be the first third-party "sys" dependency this std-only server
//! avoids).
//!
//! Semantics match the familiar API: `acquire_owned` blocks until a permit is
//! free and returns a guard that returns it on drop. Panic-safe: poisoned
//! mutexes are treated as unlocked (into_inner) rather than unwinding.

use std::sync::{Arc, Condvar, Mutex};

/// A counter of available permits plus a condvar to wait on when empty.
pub struct Semaphore {
    available: Mutex<usize>,
    changed: Condvar,
}

/// RAII permit. Releasing happens automatically when the worker thread ends
/// and this guard is dropped, however the handler exits.
pub struct SemaphorePermit {
    sem: Arc<Semaphore>,
}

impl Semaphore {
    /// Create a semaphore with `permits` available slots. Panics on zero —
    /// a listener with zero capacity can never accept.
    pub fn new(permits: usize) -> Self {
        assert!(permits > 0, "Semaphore::new(0) has no capacity");
        Self {
            available: Mutex::new(permits),
            changed: Condvar::new(),
        }
    }

    /// Block until a permit is free, then take it. `Arc<Self>` receiver so
    /// the returned guard can own the Arc and release the permit after the
    /// semaphore may have been dropped elsewhere.
    pub fn acquire_owned(self: &Arc<Self>) -> SemaphorePermit {
        let mut available = lock(&self.available);
        while *available == 0 {
            available = self
                .changed
                .wait(available)
                .unwrap_or_else(|p| p.into_inner());
        }
        *available -= 1;
        SemaphorePermit { sem: Arc::clone(self) }
    }

    fn release(&self) {
        let mut available = lock(&self.available);
        *available += 1;
        self.changed.notify_one();
    }
}

impl Drop for SemaphorePermit {
    fn drop(&mut self) {
        self.sem.release();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}
