#!/usr/bin/env bash
# run_jcsse_benchmarks.sh
# Run all JCSSE 2026 camera-ready benchmarks in order.
#
# Usage (from anywhere):
#   bash Code/benchmark/run_jcsse_benchmarks.sh
#
# Or from inside benchmark/:
#   bash run_jcsse_benchmarks.sh
#
# Results saved to: Code/results/bench_*.json
# Estimated total time on RPi 4: ~45 min

set -euo pipefail

# ── Resolve Code/ as working directory ─────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CODE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$CODE_DIR"

# ── Colours ─────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Helpers ─────────────────────────────────────────────────────
step=0
pass=0
fail=0
declare -A durations

run_bench() {
    local name="$1"
    local script="$SCRIPT_DIR/$2"
    step=$((step + 1))

    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  [$step/6] $name${NC}"
    echo -e "${CYAN}  script : $script${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"

    local t_start=$SECONDS
    if node "$script"; then
        local elapsed=$((SECONDS - t_start))
        durations["$name"]="${elapsed}s"
        echo -e "${GREEN}  ✓ Done in ${elapsed}s${NC}"
        pass=$((pass + 1))
    else
        local elapsed=$((SECONDS - t_start))
        durations["$name"]="FAILED"
        echo -e "${RED}  ✗ FAILED after ${elapsed}s${NC}"
        fail=$((fail + 1))
        echo -e "${RED}  Continuing with next benchmark...${NC}"
    fi
}

# ── Preflight checks ────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  JCSSE 2026 Camera-Ready — Full Benchmark Suite"
echo "  Working dir : $CODE_DIR"
echo "  Node        : $(node --version)"
echo "  Started     : $(date)"
echo "  Est. time   : ~45 min on RPi 4"
echo "════════════════════════════════════════════════════════"

for req in keys/verification_key.json keys/ulp_v2v_auth_final.zkey build/input.json; do
    if [[ ! -f "$req" ]]; then
        echo -e "${RED}ERROR: Missing required file: $req${NC}"
        echo "Make sure you are running from the Code/ directory and"
        echo "that the circuit build and key generation have been completed."
        exit 1
    fi
done
echo -e "${GREEN}  Preflight OK — keys and build files found.${NC}"

mkdir -p results

# ── Run benchmarks ──────────────────────────────────────────────

run_bench "ECDSA-P256 Baseline (0.197 ms claim)"    "bench_ecdsa_baseline.js"
run_bench "Single Groth16 Verify (~80 ms claim)"    "bench_single_verify.js"
run_bench "Wu et al. CLSS Comparison (7.2 ms)"      "bench_wu_clss.js"
run_bench "Jiang & Guo Lattice-ZKP (187 ms)"        "bench_jiang_lattice.js"
run_bench "Offline Proving: snarkjs + rapidsnark"   "bench_rapidsnark.js"
run_bench "Batch Groth16 Verify (k=18,30,50)"       "bench_batch_verify.js"

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Run complete: $(date)"
echo "  Passed: $pass / $((pass + fail))"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  Timings:"
for name in \
    "ECDSA-P256 Baseline (0.197 ms claim)" \
    "Single Groth16 Verify (~80 ms claim)" \
    "Wu et al. CLSS Comparison (7.2 ms)" \
    "Jiang & Guo Lattice-ZKP (187 ms)" \
    "Offline Proving: snarkjs + rapidsnark" \
    "Batch Groth16 Verify (k=18,30,50)"; do
    printf "  %-45s %s\n" "$name" "${durations[$name]:-skipped}"
done

echo ""
echo "  Result files:"
for f in results/bench_ecdsa_baseline.json \
          results/bench_single_verify.json \
          results/bench_wu_clss.json \
          results/bench_jiang_lattice.json \
          results/bench_rapidsnark.json \
          results/bench_batch_verify.json; do
    if [[ -f "$f" ]]; then
        echo -e "  ${GREEN}✓${NC} $f"
    else
        echo -e "  ${RED}✗${NC} $f  (missing — check for errors above)"
    fi
done

echo ""
echo "  Numbers to cross-check against the paper:"
echo "  bench_ecdsa_baseline.json  → sign_mean_ms        should be ≈0.197"
echo "  bench_single_verify.json   → mean_ms             update paper if >5 ms off"
echo "  bench_wu_clss.json         → T_auth_total_ms     should be ≈7.2"
echo "  bench_jiang_lattice.json   → T_auth_total_ms     should be ≈187"
echo "  bench_rapidsnark.json      → rapidsnark_mean_ms  should be ≈1359"
echo "                               snarkjs_mean_ms     should be ≈3766"
echo "  bench_batch_verify.json    → k=18: ≈242 ms, k=30: ≈425 ms, k=50: ≈701 ms"
echo "════════════════════════════════════════════════════════"
