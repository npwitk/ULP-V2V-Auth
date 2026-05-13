#!/usr/bin/env bash
# run_native_bench.sh — Build and run the native Groth16 batch-verify benchmark
#
# MUST be run from the repository root (same directory as keys/ and results/).
# Requires: rustup + cargo (install via https://rustup.rs/ if not present)
#
# Usage:
#   cd /path/to/ULP-V2V-Auth
#   bash benchmark/run_native_bench.sh
#
# Output: results/bench_batch_native.json

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATE_DIR="$REPO_ROOT/benchmark/batch_verify_native"
OUT_JSON="$REPO_ROOT/results/bench_batch_native.json"

echo "========================================================================"
echo "  ULP-V2V-Auth — Native Groth16 Batch-Verify Benchmark"
echo "  Measures true algebraic speedup without JavaScript/BigInt overhead"
echo "========================================================================"

# Check prerequisites
if ! command -v cargo &>/dev/null; then
    echo ""
    echo "ERROR: cargo not found. Install Rust via:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "  source \$HOME/.cargo/env"
    exit 1
fi

for f in "$REPO_ROOT/keys/verification_key.json" "$REPO_ROOT/results/dcv_proofs.json"; do
    if [[ ! -f "$f" ]]; then
        echo "Missing: $f"
        echo "Run the following first to generate the proof pool:"
        echo "  node benchmark/bench_dcv.js"
        exit 1
    fi
done

echo ""
echo "[1/2] Building release binary..."
cargo build --release --manifest-path "$CRATE_DIR/Cargo.toml" 2>&1

BINARY="$CRATE_DIR/target/release/batch_verify_native"
if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: build succeeded but binary not found at $BINARY"
    exit 1
fi
echo "      Binary: $BINARY"

echo ""
echo "[2/2] Running benchmark from repo root..."
echo "      (reads keys/ and results/ relative to cwd)"
echo ""

# Run from repo root so relative paths match other benchmarks
cd "$REPO_ROOT"
"$BINARY"

echo ""
echo "========================================================================"
echo "  Done. Results in: $OUT_JSON"
echo ""
echo "  How to update the paper (06_experiments.tex §Batch Verification):"
echo "    Open results/bench_batch_native.json and note the k=30 row."
echo "    - If actual_speedup ≈ 2.73-3.5: JS overhead is real but minor."
echo "    - If actual_speedup > 3.5:      final-exp savings dominate over"
echo "      pairing count, update theoretical formula commentary in §IV."
echo "========================================================================"
