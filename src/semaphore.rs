//! A minimal non-blocking counting semaphore built on std primitives.
//!
//! std::sync::Semaphore is not stable on this toolchain (unresolved import
//! on rustc 1.91), so here is a tiny permit pool guarded by a Mutex. Used by
//! main.rs to bound the number of concurrently alive connection threads
//! (→ DESIGN.md bounded concurrency; a third-party semaphore crate would be
//! the first "sys" dependency this std-only server avoids).
//!
//! The API is deliberately non-blocking — only `try_acquire_owned`. The
//! accept loop must never park waiting for a permit (a blocked accept loop
//! makes a saturated server look hung); it takes a permit when one is free
//! and rejects the surplus inline otherwise (→ GitHub issue: clean 503 on
//! backpressure, not a hang). Panic-safe: a poisoned mutex is treated as
//! unlocked (into_inner) rather than unwinding.

use std::sync::{Arc, Mutex};

/// A counter of available permits.
pub struct Semaphore {
    available: Mutex<usize>,
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
        }
    }

    /// Try to take a permit without blocking. Returns None when all permits
    /// are held — the caller decides how to answer the excess demand (the
    /// accept loop in main.rs rejects it inline). `Arc<Self>` receiver so the
    /// returned guard can own the Arc and release the permit after the
    /// semaphore may have been dropped elsewhere.
    pub fn try_acquire_owned(self: &Arc<Self>) -> Option<SemaphorePermit> {
        let mut available = lock(&self.available);
        if *available == 0 {
            return None;
        }
        *available -= 1;
        Some(SemaphorePermit { sem: Arc::clone(self) })
    }

    fn release(&self) {
        let mut available = lock(&self.available);
        *available += 1;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_acquire_fails_when_full_and_succeeds_when_released() {
        let sem = Arc::new(Semaphore::new(2));

        let a = sem.try_acquire_owned().expect("first permit free");
        let b = sem.try_acquire_owned().expect("second permit free");
        assert!(sem.try_acquire_owned().is_none(), "pool is exhausted");

        // Dropping one permit frees a slot for the next taker.
        drop(b);
        assert!(sem.try_acquire_owned().is_some(), "released permit reusable");

        // The guard still held at the end releases on drop (no leak):
        drop(a);
        assert!(sem.try_acquire_owned().is_some(), "all permits recycled");
    }

    /// A panic in a thread that holds a permit must not leak it: unwinding
    /// drops the `SemaphorePermit` guard, whose `Drop` releases the slot. The
    /// audit's point is that even a panicking worker returns its permit.
    ///
    /// Caveat recorded in the audit note: production builds use
    /// `panic = "abort"` (Cargo.toml [profile.release]), so this Drop-on-
    /// unwind path only executes under the dev/test profile. In release a
    /// worker panic aborts the whole process — which is fail-closed (no
    /// half-open state), not a permit leak. The property tested here is the
    /// one that matters under `cargo test` and any future unwind-enabled
    /// profile.
    #[test]
    fn permit_is_returned_when_holder_thread_panics() {
        let sem = Arc::new(Semaphore::new(1));

        let worker = {
            let sem = Arc::clone(&sem);
            std::thread::spawn(move || {
                let _permit = sem.try_acquire_owned().expect("permit free for worker");
                // The worker dies while still holding the permit.
                panic!("worker panics while holding a permit");
            })
        };

        // The panic propagates out of the thread; joining surfaces it.
        assert!(
            worker.join().is_err(),
            "the worker panicked, so join returns Err"
        );

        // Unwinding dropped the guard → the permit is back in the pool.
        assert!(
            sem.try_acquire_owned().is_some(),
            "permit must be recovered after the holder panics"
        );
    }
}
