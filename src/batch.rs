//! Compressing many files without managing threads: queue paths on a
//! [`Batch`] (or hand an iterator to [`compress_files`]) and read results
//! back. A fixed set of driver threads does each file's reading, staging,
//! writing and verification, while the shared rayon pool (one thread per
//! core) does all the encoding, so disk waits never hold up a compressor
//! thread. Paths wait in a bounded queue, so a stream of millions is never
//! all in memory, and the input budget (`crate::budget`) bounds what the
//! files in flight hold.

use crate::control::Control;
use crate::engine::{self, Outcome};
use crate::policy::Config;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

/// Paths queued ahead of the drivers. [`Batch::add`] blocks beyond this.
const QUEUE_BOUND: usize = 1024;

/// Twice the compressor pool's size: enough files in flight that while one
/// waits on the disk, the others keep every core encoding.
pub fn default_drivers() -> usize {
    2 * rayon::current_num_threads()
}

/// One file's result, in completion order.
#[derive(Debug)]
pub struct FileResult<T = Outcome> {
    pub path: PathBuf,
    pub outcome: io::Result<T>,
}

/// Files queued for compression under one `Config` and `Control`.
///
/// Cancelling `ctl` stops new paths being accepted; files already queued
/// come back as `Outcome::Cancelled` without being touched. Dropping the
/// `Batch` without calling [`finish`](Batch::finish) lets queued files
/// finish but discards their results.
pub struct Batch {
    paths: SyncSender<PathBuf>,
    results: Results,
    ctl: Arc<Control>,
}

impl Batch {
    /// Starts [`default_drivers`] driver threads.
    pub fn new(cfg: Config, ctl: Arc<Control>) -> io::Result<Batch> {
        Batch::with_drivers(cfg, ctl, default_drivers())
    }

    pub fn with_drivers(cfg: Config, ctl: Arc<Control>, drivers: usize) -> io::Result<Batch> {
        let driver_ctl = Arc::clone(&ctl);
        let (paths, rx) = start_drivers(drivers, move |path| engine::compress_file_with(path, &cfg, &driver_ctl))?;
        Ok(Batch { paths, results: Results { rx }, ctl })
    }

    /// Queues `path`, waiting while the queue is full. Returns `false`
    /// without queueing it once the batch's `Control` is cancelled.
    pub fn add(&self, path: PathBuf) -> bool {
        !self.ctl.is_cancelled() && self.paths.send(path).is_ok()
    }

    /// Results ready now, without waiting.
    pub fn ready(&self) -> impl Iterator<Item = FileResult> + '_ {
        self.results.rx.try_iter()
    }

    /// Stops accepting paths. The iterator yields every result not yet
    /// taken and ends once the last queued file is done.
    pub fn finish(self) -> Results {
        self.results
    }
}

/// Compresses every path `paths` yields, reading it lazily. Returns once
/// the work is started; the iterator yields results as files finish and
/// ends after the last one. Cancelling `ctl` stops reading `paths`.
pub fn compress_files<I>(paths: I, cfg: Config, ctl: Arc<Control>) -> io::Result<Results>
where
    I: IntoIterator<Item = PathBuf>,
    I::IntoIter: Send + 'static,
{
    let Batch { paths: queue, results, ctl } = Batch::new(cfg, ctl)?;
    feed(paths.into_iter(), queue, move || ctl.is_cancelled())?;
    Ok(results)
}

/// Sends every path from `paths` into `queue` from a thread of its own,
/// stopping early once `stop` says so or the drivers are gone.
pub(crate) fn feed<I>(paths: I, queue: SyncSender<PathBuf>, stop: impl Fn() -> bool + Send + 'static) -> io::Result<()>
where
    I: Iterator<Item = PathBuf> + Send + 'static,
{
    thread::Builder::new().name("apfscompress-feeder".into()).spawn(move || {
        for path in paths {
            if stop() || queue.send(path).is_err() {
                break;
            }
        }
    })?;
    Ok(())
}

/// Results of a [`Batch`] or [`compress_files`], in completion order.
pub struct Results {
    rx: Receiver<FileResult>,
}

impl Iterator for Results {
    type Item = FileResult;
    fn next(&mut self) -> Option<FileResult> {
        self.rx.recv().ok()
    }
}

/// Starts `drivers` threads that take paths from a bounded queue and run
/// `op` on each, until the queue is closed and empty or nobody is reading
/// results. A panic in `op` (a bug) becomes that file's error rather than
/// taking the thread, or the process, down with it.
pub(crate) fn start_drivers<T, F>(drivers: usize, op: F) -> io::Result<(SyncSender<PathBuf>, Receiver<FileResult<T>>)>
where
    T: Send + 'static,
    F: Fn(&Path) -> io::Result<T> + Send + Sync + 'static,
{
    let (paths_tx, paths_rx) = mpsc::sync_channel::<PathBuf>(QUEUE_BOUND);
    let (results_tx, results_rx) = mpsc::channel();
    let paths_rx = Arc::new(Mutex::new(paths_rx));
    let op = Arc::new(op);
    for n in 0..drivers.max(1) {
        let (paths_rx, results_tx, op) = (Arc::clone(&paths_rx), results_tx.clone(), Arc::clone(&op));
        thread::Builder::new()
            .name(format!("apfscompress-driver-{n}"))
            .spawn(move || loop {
                let next = paths_rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
                let Ok(path) = next else { break };
                let outcome = panic::catch_unwind(AssertUnwindSafe(|| op(&path)))
                    .unwrap_or_else(|_| Err(io::Error::other("internal error: apfscompress panicked on this file")));
                if results_tx.send(FileResult { path, outcome }).is_err() {
                    break;
                }
            })?;
    }
    Ok((paths_tx, results_rx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn text(n: usize) -> Vec<u8> {
        b"batch files compress through the shared pool. ".repeat(n)
    }

    #[test]
    fn every_path_gets_exactly_one_result() {
        let dir = tempdir().unwrap();
        let mut expected = Vec::new();
        for i in 0..40 {
            let path = dir.path().join(format!("f{i}.txt"));
            fs::write(&path, text(200 + i * 500)).unwrap();
            expected.push(path);
        }
        let results: Vec<FileResult> =
            compress_files(expected.clone(), Config::default(), Arc::new(Control::new())).unwrap().collect();

        let mut seen: Vec<PathBuf> = results.iter().map(|r| r.path.clone()).collect();
        seen.sort();
        expected.sort();
        assert_eq!(seen, expected);
        for (i, r) in results.iter().enumerate() {
            assert!(matches!(r.outcome, Ok(Outcome::Compressed { .. })), "{i}: {:?}", r.outcome);
        }
        for path in &expected {
            let n: usize = path.file_stem().unwrap().to_str().unwrap()[1..].parse().unwrap();
            assert_eq!(fs::read(path).unwrap(), text(200 + n * 500));
        }
    }

    #[test]
    fn a_cancelled_batch_refuses_new_paths_and_leaves_queued_files_alone() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.txt");
        fs::write(&path, text(1000)).unwrap();
        let ctl = Arc::new(Control::new());
        ctl.cancel();
        let batch = Batch::with_drivers(Config::default(), Arc::clone(&ctl), 2).unwrap();
        assert!(!batch.add(path.clone()));
        assert_eq!(batch.finish().count(), 0);
        assert_eq!(fs::read(&path).unwrap(), text(1000));
    }

    #[test]
    fn a_panic_on_one_file_becomes_its_error() {
        let (queue, results) = start_drivers(2, |path: &Path| {
            if path.ends_with("bad") {
                panic!("simulated bug");
            }
            Ok(())
        })
        .unwrap();
        for name in ["a", "bad", "b"] {
            queue.send(PathBuf::from(name)).unwrap();
        }
        drop(queue);
        let mut results: Vec<(String, bool)> =
            results.iter().map(|r| (r.path.display().to_string(), r.outcome.is_ok())).collect();
        results.sort();
        assert_eq!(results, [("a".into(), true), ("b".into(), true), ("bad".into(), false)]);
    }
}
