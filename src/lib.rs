//! Transparent APFS file compression for macOS.
//!
//! apfscompress is a command-line tool; see the
//! [README](https://github.com/ecc521/apfscompress#readme) for usage. This
//! library shares code between the CLI and its benchmarks, and its modules
//! build only on macOS.

#[cfg(not(any(target_os = "macos", docsrs)))]
compile_error!("apfscompress requires macOS");

#[cfg(target_os = "macos")]
pub mod algo;
#[cfg(target_os = "macos")]
pub mod batch;
#[cfg(target_os = "macos")]
pub mod budget;
#[cfg(target_os = "macos")]
pub mod chunker;
#[cfg(target_os = "macos")]
pub mod control;
#[cfg(target_os = "macos")]
pub mod decmpfs;
#[cfg(target_os = "macos")]
pub mod dmg;
#[cfg(target_os = "macos")]
pub mod engine;
#[cfg(target_os = "macos")]
pub mod estimate;
#[cfg(target_os = "macos")]
pub mod fsops;
#[cfg(target_os = "macos")]
pub mod openfiles;
#[cfg(target_os = "macos")]
pub mod policy;
#[cfg(target_os = "macos")]
pub mod swap;
#[cfg(target_os = "macos")]
pub mod sys;
#[cfg(target_os = "macos")]
pub mod walk;
