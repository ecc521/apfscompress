# Contributing

## License of contributions

By submitting a contribution, you confirm that you have the right to license
it and permit its use under any of these licenses:

- [MPL-2.0](https://www.mozilla.org/MPL/2.0/)
- [MIT](https://opensource.org/license/mit)
- [BSD-3-Clause](https://opensource.org/license/bsd-3-clause)

If your contribution includes code whose license prevents this grant, identify
it in the pull request.

If you consulted disassembly or other non-public material, list exactly what
you consulted in the pull request so maintainers can review its licensing implications.

## Building and testing

Source builds require macOS and a sibling `../crush-lz` checkout.

```bash
cargo build --release
cargo test
```

The default tests include short conformance and decoder-fuzzing runs.
For longer campaigns:

```bash
CONFORMANCE_ITERS=20000 CONFORMANCE_SEED=7 \
  cargo test --release --test decmpfs_conformance -- --ignored --nocapture
DECODER_ITERS=200000 DECODER_SEED=3 \
  cargo test --release --test decmpfs_decoder_fuzz -- --ignored --nocapture
```

See [decmpfs_conformance.rs](tests/decmpfs_conformance.rs) for scratch-volume
setup and case replay, and [decmpfs_decoder_fuzz.rs](tests/decmpfs_decoder_fuzz.rs)
for decoder comparison options.

## Benchmarks

Run `bench/race_frontier.sh` after encoder changes. Review the resulting
frontiers before updating the README tables or `policy::race_profile`.
See the [benchmark method](README.md#benchmarks) for measurement scope.
