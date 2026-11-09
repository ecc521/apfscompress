# Third-party code and licensing

Project code is licensed under MPL-2.0; see [LICENSE](LICENSE). Dependencies
and their license terms are listed below.

## crush-lz

The `crushlzfse`, `lzbitmap` and `crushlz4` crates from
[crush-lz](https://github.com/ecc521/crush-lz), MPL-2.0, plus:

- LZFSE and LZVN (`crushlzfse`): derived from Apple's LZFSE reference
  implementation. Copyright (c) 2015-2016, Apple Inc. BSD-3-Clause.
- LZBITMAP (`lzbitmap`): derived from Corellium's LZBITMAP implementation.
  Copyright (c) 2022 Corellium LLC. MIT.
- LZ4 (`crushlz4`): vendors upstream LZ4's block encoder unmodified.
  Copyright (c) 2011-2020, Yann Collet. BSD-2-Clause.

See crush-lz's
[THIRD-PARTY.md](https://github.com/ecc521/crush-lz/blob/main/THIRD-PARTY.md)
for notices and license scope.

## libdeflate

Used for zlib (decmpfs types 3/4) through the `libdeflater` and
`libdeflate-sys` crates (Apache-2.0), which vendor libdeflate's C source.
Copyright 2016 Eric Biggers; Copyright 2024 Google LLC. MIT.

## Rust crates

The remaining dependencies (clap, rayon, libc, memmap2, uuid and their
transitive dependencies) are MIT and/or Apache-2.0; `unicode-ident`
additionally carries Unicode-3.0. Run `cargo tree -e normal -f "{p} {l}"`
to list dependencies and their declared licenses.
