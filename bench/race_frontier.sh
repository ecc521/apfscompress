#!/bin/sh
# Measures the codec families and analyzes races for README and race-profile review.
# Writes TSV measurements and a summary; does not edit tables or policy::race_profile.
#
#   bench/race_frontier.sh [corpus-dir] [out-dir]
#
# The corpus defaults to crush-lz's standard corpus, checked out as a sibling
# of this repo; build it there with `cargo run -p xtask -- corpus fetch` and
# `cargo run -p xtask -- corpus build`. Encode speeds use every core, so run
# this on an otherwise idle machine.
set -eu
cd "$(dirname "$0")/.."
corpus=${1:-../crush-lz/corpus/segments/main}
out=${2:-target/race_frontier}
mkdir -p "$out"
cargo build --release -p apfscompress-bench --bin race_frontier
bin=target/release/race_frontier
for family in lzfse zlib lzbitmap lz4; do
    "$bin" sweep "$family" "$corpus" "$out/$family.tsv"
done
"$bin" analyze "$out/lzfse.tsv" "$out/zlib.tsv" "$out/lzbitmap.tsv" "$out/lz4.tsv" | tee "$out/summary.txt"
