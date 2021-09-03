#!/usr/bin/env bash

set -e

cd "$(dirname "$0")"

cd ..

cargo build --release --features=runtime-benchmarks

bench_run() {
  pallet=$1
  output=$2
  ./target/release/node-threshold-signature benchmark \
    --chain=dev \
    --steps=50 \
    --repeat=20 \
    --pallet="$pallet" \
    --extrinsic="*" \
    --execution=wasm \
    --wasm-execution=compiled \
    --heap-pages=4096 \
    --output="$output" \
    --template=./scripts/pallet-weight-template.hbs

  rustfmt "$output"
}

bench_run pallet_threshold_signature            ./pallets/threshold-signature/src/weights.rs

