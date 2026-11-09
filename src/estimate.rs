//! Tree-level savings prediction: walks a directory and asks
//! `engine::estimate_file` for a probe-and-extrapolate prediction per
//! eligible file, instead of a real compression. Bounding work to
//! `cfg.probe_size` per file is what makes this viable over a whole disk;
//! see `engine::estimate_chunked` for the accuracy tradeoff that buys.
//!
//! A pure library function returning a `TreeEstimate` value, not just CLI
//! glue; reports a point prediction, not a range - `exact_files`/
//! `estimated_files` show how much rests on extrapolation.

use crate::batch;
use crate::engine::{self, EstimateFileOutcome};
use crate::policy::{Config, SkipReason};
use crate::walk;
use std::collections::HashMap;
use std::io;
use std::path::Path;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TreeEstimate {
    /// Files that passed `should_skip` and got a real prediction (whether
    /// exact or extrapolated) - excludes `not_worthwhile_files`.
    pub eligible_files: u64,
    /// Of `eligible_files`, how many fit entirely inside `cfg.probe_size` -
    /// their prediction is the real, fully-computed answer, not extrapolated.
    pub exact_files: u64,
    /// Of `eligible_files`, how many were larger than `cfg.probe_size` and so
    /// had their compressed size extrapolated from the probe window alone.
    pub estimated_files: u64,
    /// Passed `should_skip` but no candidate algorithm cleared `max_ratio`.
    pub not_worthwhile_files: u64,
    /// A file could be stat'd during the walk but not opened/mapped for
    /// estimation (permissions, a race with deletion, etc.) - counted, not
    /// fatal to the rest of the walk.
    pub error_files: u64,
    pub skipped_files_by_reason: HashMap<SkipReason, u64>,
    /// Sum of `original_size` over `eligible_files` only - not the whole
    /// tree, so this is directly comparable to `predicted_compressed_bytes`.
    pub original_bytes: u64,
    pub predicted_compressed_bytes: u64,
}

/// Walks `root` (a file or a directory) and predicts total compression
/// savings under `cfg`, without writing or fully compressing anything. See
/// this module's doc comment for why the result is a point estimate, not a
/// range, and `engine::estimate_file` for the per-file mechanics.
pub fn estimate_tree(root: &Path, cfg: &Config) -> io::Result<TreeEstimate> {
    let files = walk::walk_files(root.to_path_buf())?;
    let cfg = cfg.clone();
    let (queue, results) = batch::start_drivers(batch::default_drivers(), move |path| engine::estimate_file(path, &cfg))?;
    batch::feed(files, queue, || false)?;

    let mut t = TreeEstimate {
        eligible_files: 0,
        exact_files: 0,
        estimated_files: 0,
        not_worthwhile_files: 0,
        error_files: 0,
        skipped_files_by_reason: HashMap::new(),
        original_bytes: 0,
        predicted_compressed_bytes: 0,
    };
    for result in results {
        match result.outcome {
            Ok(EstimateFileOutcome::Estimated { original_size, predicted_compressed_size, exact, .. }) => {
                t.eligible_files += 1;
                if exact {
                    t.exact_files += 1;
                } else {
                    t.estimated_files += 1;
                }
                t.original_bytes += original_size;
                t.predicted_compressed_bytes += predicted_compressed_size;
            }
            Ok(EstimateFileOutcome::NotWorthwhile { .. }) => t.not_worthwhile_files += 1,
            Ok(EstimateFileOutcome::Skipped(reason)) => *t.skipped_files_by_reason.entry(reason).or_insert(0) += 1,
            Err(_) => t.error_files += 1,
        }
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Algorithms;
    use crate::algo::Algo;
    use tempfile::tempdir;

    fn compressible_bytes(n: usize) -> Vec<u8> {
        let motif = b"the quick brown fox jumps over the lazy dog ";
        (0..n).map(|i| motif[i % motif.len()]).collect()
    }

    #[test]
    fn empty_dir_reports_all_zeros() {
        let dir = tempdir().unwrap();
        let cfg = Config::default();
        let result = estimate_tree(dir.path(), &cfg).unwrap();
        assert_eq!(result, TreeEstimate::default());
    }

    #[test]
    fn single_small_file_is_exact_and_matches_engine_estimate_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.txt");
        std::fs::write(&path, compressible_bytes(50_000)).unwrap();

        let cfg = Config { algorithms: Algorithms::single(Algo::Lzfse), ..Config::default() };
        let result = estimate_tree(dir.path(), &cfg).unwrap();

        let engine::EstimateFileOutcome::Estimated { original_size, predicted_compressed_size, exact, .. } =
            engine::estimate_file(&path, &cfg).unwrap()
        else {
            panic!("expected a real single-file compressible under max_ratio");
        };
        assert_eq!(result.eligible_files, 1);
        assert_eq!(result.exact_files, 1);
        assert_eq!(result.estimated_files, 0);
        assert!(exact, "a 50KB file is well under the default 5MiB probe_size");
        assert_eq!(result.original_bytes, original_size);
        assert_eq!(result.predicted_compressed_bytes, predicted_compressed_size);
    }

    #[test]
    fn file_larger_than_probe_size_is_extrapolated_not_exact() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("big.txt");
        // 3 chunks' worth, well past a tiny probe_size.
        std::fs::write(&path, compressible_bytes(crate::decmpfs::CHUNK_SIZE * 3)).unwrap();

        let cfg = Config {
            algorithms: Algorithms::single(Algo::Lzfse),
            probe_size: crate::decmpfs::CHUNK_SIZE as u64, // window = first chunk only
            ..Config::default()
        };
        let result = estimate_tree(dir.path(), &cfg).unwrap();
        assert_eq!(result.eligible_files, 1);
        assert_eq!(result.exact_files, 0);
        assert_eq!(result.estimated_files, 1);
        assert!(result.predicted_compressed_bytes > 0);
        assert!(result.predicted_compressed_bytes < result.original_bytes);
    }

    #[test]
    fn skipped_files_are_counted_by_reason_not_folded_into_eligible() {
        // Nested symlinks are filtered by walk_files itself (see walk.rs),
        // so ExtensionExcluded is used instead - a reason should_skip
        // actually produces.
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.txt");
        std::fs::write(&real, compressible_bytes(50_000)).unwrap();
        let excluded = dir.path().join("skip_me.jpg");
        std::fs::write(&excluded, compressible_bytes(50_000)).unwrap();

        let cfg = Config { skip_extensions: vec!["jpg".to_string()], ..Config::default() };
        let result = estimate_tree(dir.path(), &cfg).unwrap();
        assert_eq!(result.eligible_files, 1); // only real.txt
        assert_eq!(result.skipped_files_by_reason.get(&SkipReason::ExtensionExcluded), Some(&1));
    }

    #[test]
    fn nonexistent_root_errors() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does_not_exist");
        assert!(estimate_tree(&missing, &Config::default()).is_err());
    }
}
