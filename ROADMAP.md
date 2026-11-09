# Roadmap

Deferred improvements to compression scheduling and memory use.

## Earlier decisions during compression

[`probe_gate` and `stream_rest`](src/engine.rs) check compressed size at the
end of a sample or batch. Potential improvements:

- **Reject within a batch:** stop dispatching chunks as soon as accumulated
  output exceeds the target. Remaining chunks cannot reduce that total.
- **Start the next phase earlier:** if accumulated output plus a worst-case
  bound for outstanding chunks meets the target, begin the next phase without
  waiting for all chunks. Outstanding work must still finish before output
  is committed.
- **Reject oversized resource forks earlier:** stop when accumulated output
  exceeds the format's 32-bit offset limit. This matters when
  `--max-file-size` is raised beyond its 4 GiB default.

These changes need tests for cancellation, pending work and output ordering.

## Discard and recompress samples

The encoder retains the winning candidate's sampled chunks and reuses them
when writing output. Memory use therefore grows with `Config::probe_size`.

An optional mode could retain only sampled sizes, discard sampled output, and
recompress the winner's sampled chunks. This would allow larger samples
without retaining their compressed output, at the cost of encoding those
chunks twice. The sample's input and encoder scratch would still require
memory. This mode should be opt-in.
