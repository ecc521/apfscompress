//! Cancellation and progress for `engine::compress_file_with`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Shared between a caller and any number of concurrent
/// `engine::compress_file_with` calls, typically one per batch of work.
/// Poll [`Control::bytes_done`] from a UI timer; call [`Control::cancel`]
/// from anywhere.
#[derive(Debug, Default)]
pub struct Control {
    cancelled: AtomicBool,
    bytes_done: AtomicU64,
}

impl Control {
    pub const fn new() -> Self {
        Control { cancelled: AtomicBool::new(false), bytes_done: AtomicU64::new(0) }
    }

    /// Asks every call sharing this `Control` to stop. Each one returns
    /// `Outcome::Cancelled` within about one 64KiB chunk's encode time,
    /// discarding its staged work; the original file is never touched. Calls
    /// started afterwards return `Cancelled` immediately.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Logical input bytes processed so far, summed over every call sharing
    /// this `Control`. Advances per chunk while a file encodes. Once a call
    /// returns anything other than `Cancelled` or an error, its file's whole
    /// logical size has been counted, skipped and rejected files included,
    /// so the total of submitted files' sizes is the denominator.
    pub fn bytes_done(&self) -> u64 {
        self.bytes_done.load(Ordering::Relaxed)
    }
}

/// One call's view of a `Control`: reports progress to it and remembers how
/// much of this file is already counted, so `finish` can add the rest.
/// Detached, it only ever reports "not cancelled".
pub(crate) struct FileProgress<'a> {
    ctl: Option<&'a Control>,
    counted: AtomicU64,
}

impl<'a> FileProgress<'a> {
    pub(crate) fn new(ctl: &'a Control) -> Self {
        FileProgress { ctl: Some(ctl), counted: AtomicU64::new(0) }
    }

    pub(crate) fn detached() -> Self {
        FileProgress { ctl: None, counted: AtomicU64::new(0) }
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.ctl.is_some_and(Control::is_cancelled)
    }

    pub(crate) fn add(&self, bytes: u64) {
        if let Some(ctl) = self.ctl {
            self.counted.fetch_add(bytes, Ordering::Relaxed);
            ctl.bytes_done.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Counts whatever part of `total` hasn't been counted yet.
    pub(crate) fn finish(&self, total: u64) {
        let counted = self.counted.load(Ordering::Relaxed);
        self.add(total.saturating_sub(counted));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish_tops_up_to_the_total_and_never_double_counts() {
        let ctl = Control::new();
        let a = FileProgress::new(&ctl);
        let b = FileProgress::new(&ctl);
        a.add(30);
        b.add(5);
        a.finish(100);
        b.finish(2); // already counted more than this: adds nothing
        assert_eq!(ctl.bytes_done(), 105);
    }

    #[test]
    fn detached_progress_is_never_cancelled() {
        let p = FileProgress::detached();
        p.add(10);
        assert!(!p.cancelled());
    }
}
