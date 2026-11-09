//! A process-wide cap on file input held in memory. Every compression and
//! estimate reads its probe sample and each batch into a buffer charged
//! against it, so input memory stays bounded however many files are in
//! flight: a file waits, holding nothing, until a running batch finishes.
//! Returned buffers are kept for reuse rather than freed.

use crate::control::FileProgress;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// Default for [`set_input_budget`]: several 32 MiB batches encoding with
/// more read and waiting behind them, so reads stay ahead of the
/// compressor pool.
pub const DEFAULT_INPUT_BUDGET: u64 = 256 * 1024 * 1024;

static INPUT: Budget = Budget::new(DEFAULT_INPUT_BUDGET);

/// Sets how many bytes of file input every compression and estimate in the
/// process may hold at once. Takes effect for the next buffer requested.
pub fn set_input_budget(bytes: u64) {
    INPUT.set_limit(bytes);
}

/// A buffer of `len` bytes charged against the process-wide budget. See
/// [`Budget::acquire`].
pub(crate) fn acquire(len: usize, prog: &FileProgress) -> Option<InputBuf<'static>> {
    INPUT.acquire(len, prog)
}

pub(crate) struct Budget {
    state: Mutex<State>,
    freed: Condvar,
}

struct State {
    limit: u64,
    used: u64,
    /// Returned buffers kept for reuse, and their total capacity.
    spare: Vec<Vec<u8>>,
    spare_bytes: u64,
}

impl Budget {
    pub(crate) const fn new(limit: u64) -> Self {
        Budget {
            state: Mutex::new(State { limit, used: 0, spare: Vec::new(), spare_bytes: 0 }),
            freed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_limit(&self, bytes: u64) {
        self.lock().limit = bytes;
        self.freed.notify_all();
    }

    /// Waits until `len` more bytes fit the budget, then returns a buffer of
    /// exactly `len` bytes, charged until it's dropped. A request larger
    /// than the whole budget goes ahead once nothing else holds any, so it
    /// can't wait forever. `None` if `prog` is cancelled while waiting.
    ///
    /// A caller must drop one buffer before acquiring another, or two
    /// callers could each wait on the other. A rayon pool thread never
    /// waits and may go over the limit instead: while it waits inside one
    /// file's encoding it can pick up another file, which would then wait
    /// on budget the first file holds. `batch` runs files on its own
    /// threads for this reason.
    pub(crate) fn acquire(&self, len: usize, prog: &FileProgress) -> Option<InputBuf<'_>> {
        let may_wait = rayon::current_thread_index().is_none();
        let mut st = self.lock();
        while may_wait && st.used > 0 && st.used + len as u64 > st.limit {
            if prog.cancelled() {
                return None;
            }
            // Timed, so a cancel is noticed without anything to wake us.
            st = self.freed.wait_timeout(st, Duration::from_millis(50)).unwrap_or_else(PoisonError::into_inner).0;
        }
        st.used += len as u64;
        let mut buf = match st.spare.pop() {
            Some(b) => {
                st.spare_bytes -= b.capacity() as u64;
                b
            }
            None => Vec::new(),
        };
        drop(st);
        buf.resize(len, 0);
        Some(InputBuf { budget: self, buf })
    }

    fn release(&self, buf: Vec<u8>) {
        let mut st = self.lock();
        st.used -= buf.len() as u64;
        // Keep it only while spare and in-use buffers together fit the
        // limit; otherwise let it go.
        if st.spare_bytes + buf.capacity() as u64 + st.used <= st.limit {
            st.spare_bytes += buf.capacity() as u64;
            st.spare.push(buf);
        }
        drop(st);
        self.freed.notify_all();
    }
}

/// Input bytes held against a [`Budget`], returned when dropped.
pub(crate) struct InputBuf<'a> {
    budget: &'a Budget,
    buf: Vec<u8>,
}

impl std::ops::Deref for InputBuf<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl std::ops::DerefMut for InputBuf<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Drop for InputBuf<'_> {
    fn drop(&mut self) {
        self.budget.release(std::mem::take(&mut self.buf));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Control;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn a_request_waits_until_it_fits() {
        let budget = Budget::new(100);
        let prog = FileProgress::detached();
        let held = budget.acquire(80, &prog).unwrap();
        let (tx, rx) = mpsc::channel();
        thread::scope(|s| {
            s.spawn(|| {
                let buf = budget.acquire(50, &FileProgress::detached()).unwrap();
                tx.send(buf.len()).unwrap();
            });
            assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "50 + 80 must not fit 100");
            drop(held);
            assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 50);
        });
    }

    #[test]
    fn an_oversized_request_runs_alone() {
        let budget = Budget::new(100);
        let buf = budget.acquire(150, &FileProgress::detached()).unwrap();
        assert_eq!(buf.len(), 150);
    }

    #[test]
    fn a_waiting_request_gives_up_when_cancelled() {
        let budget = Budget::new(100);
        let _held = budget.acquire(100, &FileProgress::detached()).unwrap();
        let ctl = Control::new();
        ctl.cancel();
        assert!(budget.acquire(10, &FileProgress::new(&ctl)).is_none());
    }

    #[test]
    fn released_buffers_are_reused() {
        let budget = Budget::new(1 << 20);
        let prog = FileProgress::detached();
        let ptr = budget.acquire(4096, &prog).unwrap().as_ptr();
        assert_eq!(budget.acquire(4096, &prog).unwrap().as_ptr(), ptr);
    }
}
