#!/bin/bash
# =============================================================================
# bench_depth_scaling.sh
#
# Benchmarks rapidsnark prove time across Merkle tree depths: 8, 12, 14, 16.
# For each depth: compiles circuit → generates zkey → generates input → times
# rapidsnark over N_WARMUP+N_RUNS iterations.
#
# Output: results/bench_depth_scaling.json
#
# Runtime on RPi 4:  ~60–90 min (zkey setup dominates, ~15 min each)
# Run:               bash scripts/bench_depth_scaling.sh
# =============================================================================

set -euo pipefail

# -------------------------------------------------------
# Config — edit if needed
# -------------------------------------------------------
DEPTHS=(8 12 14 16)
N_WARMUP=3
N_RUNS=20
CIRCUIT_SRC="circuits/ulp_v2v_auth.circom"
OUT_JSON="results/bench_depth_scaling.json"

# Colors
GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${BLUE}[bench]${NC} $1"; }
ok()   { echo -e "${GREEN}[ok]${NC}    $1"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $1"; }

# -------------------------------------------------------
# Pre-flight checks
# -------------------------------------------------------
for cmd in circom node; do
    command -v "$cmd" &>/dev/null || { echo "ERROR: $cmd not found"; exit 1; }
done

# Find rapidsnark binary
RAPIDSNARK=""
for candidate in \
    "$(command -v rapidsnark 2>/dev/null || true)" \
    "$HOME/rapidsnark/build_prover/src/prover" \
    "$HOME/rapidsnark/build_prover/prover" \
    "$HOME/rapidsnark/build/src/prover" \
    "/usr/local/bin/rapidsnark" \
    "/usr/local/bin/prover"; do
    [ -x "$candidate" ] && { RAPIDSNARK="$candidate"; break; }
done
[ -z "$RAPIDSNARK" ] && { echo "ERROR: rapidsnark not found. Run: bash scripts/install_rapidsnark.sh"; exit 1; }
ok "rapidsnark: $RAPIDSNARK"

mkdir -p results build/depth_scaling

# -------------------------------------------------------
# Helper: generate input.json for a given depth
# Writes to $1 (output path), uses depth $2
# -------------------------------------------------------
gen_input() {
    local OUT="$1"
    local DEPTH="$2"
    node --input-type=module - "$DEPTH" "$OUT" << 'EOF'
import { buildPoseidon } from "circomlibjs";
import fs from "fs";

const DEPTH      = parseInt(process.argv[2]);
const OUT        = process.argv[3];
const NUM_LEAVES = 1 << DEPTH;
const LEAF_INDEX = 3;

const AST = {
    sid:    BigInt("0x1A2B3C4D5E6F7A8B"),
    tStart: BigInt(1700000000),
    tEnd:   BigInt(1700002800),
    cap:    BigInt(1),
    r:      BigInt("0xDEADBEEFCAFEBABE1234"),
};
const T_CURRENT = BigInt(1700001400);
const MESSAGE   = BigInt("0xBEEF0001CAFE0002DEAD0003BABE0004");

const poseidon = await buildPoseidon();
const F = poseidon.F;
const hash = (...args) => F.toObject(poseidon(args));

const ourLeaf = hash(AST.sid, AST.tStart, AST.tEnd, AST.cap, AST.r);
const leaves  = Array.from({ length: NUM_LEAVES }, (_, i) =>
    i === LEAF_INDEX ? ourLeaf : hash(BigInt(i + 10000)));

// Build tree bottom-up
const tree = [leaves.slice()];
let cur = leaves;
while (cur.length > 1) {
    const next = [];
    for (let i = 0; i < cur.length; i += 2)
        next.push(hash(cur[i], cur[i + 1]));
    tree.push(next);
    cur = next;
}
const merkleRoot = cur[0];

// Extract Merkle path for LEAF_INDEX
const pathElements = [], pathIndices = [];
let idx = LEAF_INDEX;
for (let l = 0; l < DEPTH; l++) {
    const isRight = idx % 2;
    pathIndices.push(isRight);
    pathElements.push(tree[l][isRight ? idx - 1 : idx + 1]);
    idx = Math.floor(idx / 2);
}

const hMessage = hash(MESSAGE, T_CURRENT);

fs.writeFileSync(OUT, JSON.stringify({
    merkleRoot:   merkleRoot.toString(),
    tCurrent:     T_CURRENT.toString(),
    hMessage:     hMessage.toString(),
    sid:          AST.sid.toString(),
    tStart:       AST.tStart.toString(),
    tEnd:         AST.tEnd.toString(),
    cap:          AST.cap.toString(),
    r:            AST.r.toString(),
    pathElements: pathElements.map(x => x.toString()),
    pathIndices:  pathIndices.map(x => x.toString()),
    message:      MESSAGE.toString(),
}, null, 2));
console.log(`  Input written (depth=${DEPTH}, ${NUM_LEAVES} leaves) → ${OUT}`);
EOF
}

# -------------------------------------------------------
# Helper: run timed benchmark for one depth
# Writes timing JSON to $1
# -------------------------------------------------------
run_bench() {
    local OUT="$1"
    local DEPTH="$2"
    local WASM="$3"
    local ZKEY="$4"
    local INPUT="$5"
    local CONSTRAINTS="$6"

    node --input-type=module - \
        "$DEPTH" "$WASM" "$ZKEY" "$INPUT" \
        "$RAPIDSNARK" "$N_WARMUP" "$N_RUNS" "$CONSTRAINTS" "$OUT" << 'EOF'
import * as snarkjs from "snarkjs";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";

const [,, depth, wasm, zkey, inputPath, rapid, nWarmupStr, nRunsStr, constraintsStr, out] = process.argv;
const N_WARMUP = parseInt(nWarmupStr);
const N_RUNS   = parseInt(nRunsStr);
const inp      = JSON.parse(fs.readFileSync(inputPath));

const TMP = os.tmpdir();
const WTNS  = `${TMP}/snap_d${depth}.wtns`;
const PROOF = `${TMP}/snap_d${depth}_proof.json`;
const PUB   = `${TMP}/snap_d${depth}_pub.json`;

// Warmup
for (let i = 0; i < N_WARMUP; i++) {
    await snarkjs.wtns.calculate(inp, wasm, { type: "file", fileName: WTNS });
    execFileSync(rapid, [zkey, WTNS, PROOF, PUB], { stdio: "pipe" });
    process.stderr.write(`  warm-up ${i + 1}/${N_WARMUP}\r`);
}
process.stderr.write("\n");

// Measured runs
const times = [];
for (let i = 0; i < N_RUNS; i++) {
    await snarkjs.wtns.calculate(inp, wasm, { type: "file", fileName: WTNS });
    const t0 = performance.now();
    execFileSync(rapid, [zkey, WTNS, PROOF, PUB], { stdio: "pipe" });
    const elapsed = performance.now() - t0;
    times.push(parseFloat(elapsed.toFixed(2)));
    process.stderr.write(`  run ${i + 1}/${N_RUNS}: ${elapsed.toFixed(0)} ms\r`);
}
process.stderr.write("\n");

const mean = times.reduce((a, b) => a + b, 0) / times.length;
const std  = Math.sqrt(times.reduce((s, x) => s + (x - mean) ** 2, 0) / times.length);

// Cleanup
for (const f of [WTNS, PROOF, PUB]) { try { fs.unlinkSync(f); } catch {} }

const result = {
    depth:           parseInt(depth),
    num_leaves:      1 << parseInt(depth),
    constraints:     parseInt(constraintsStr) || null,
    n_warmup:        N_WARMUP,
    n_runs:          N_RUNS,
    prove_mean_ms:   parseFloat(mean.toFixed(2)),
    prove_std_ms:    parseFloat(std.toFixed(2)),
    prove_times_ms:  times,
};
fs.writeFileSync(out, JSON.stringify(result, null, 2));
console.log(`  depth-${depth}: mean=${mean.toFixed(1)} ms  std=${std.toFixed(1)} ms`);
EOF
}

# -------------------------------------------------------
# Main loop: for each depth
# -------------------------------------------------------
DEPTH_JSON_FILES=()

for DEPTH in "${DEPTHS[@]}"; do
    echo ""
    log "========== Depth ${DEPTH} ($(node -e "console.log(1<<${DEPTH})") leaves) =========="

    D_DIR="build/depth_scaling/depth${DEPTH}"
    mkdir -p "$D_DIR"

    # ------------------------------------------------------------------
    # 1. Create depth-specific circom file
    # ------------------------------------------------------------------
    CIRC_TMP="$D_DIR/ulp_auth_d${DEPTH}.circom"
    sed "s/component main.*= ULP_V2V_Auth([0-9]*);/component main {public [merkleRoot, tCurrent, hMessage]} = ULP_V2V_Auth(${DEPTH});/" \
        "$CIRCUIT_SRC" > "$CIRC_TMP"
    log "Circuit: $CIRC_TMP"

    # ------------------------------------------------------------------
    # 2. Compile circuit
    # ------------------------------------------------------------------
    if [ ! -f "$D_DIR/ulp_auth_d${DEPTH}.r1cs" ]; then
        log "Compiling..."
        circom "$CIRC_TMP" --r1cs --wasm --sym -o "$D_DIR" -l ./node_modules
        ok "Compiled"
    else
        ok "Already compiled, skipping."
    fi

    # Get constraint count
    CONSTRAINTS=$(npx snarkjs r1cs info "$D_DIR/ulp_auth_d${DEPTH}.r1cs" 2>&1 \
        | grep -i "Constraints" | grep -o "[0-9]*" | tail -1 || echo "0")
    log "Constraints: $CONSTRAINTS"

    # ------------------------------------------------------------------
    # 3. Select Powers of Tau
    #    pot13 covers up to 8192 constraints (depth ≤ 12)
    #    pot14 covers up to 16384 constraints (depth ≤ 16)
    # ------------------------------------------------------------------
    if [ "$DEPTH" -le 12 ]; then
        POT="build/pot13_final.ptau"
    else
        POT="build/pot14_final.ptau"
    fi

    if [ ! -f "$POT" ]; then
        warn "$POT not found — generating (this takes ~15 min on RPi 4)..."
        POT_N=$(basename "$POT" | grep -o 'pot[0-9]*' | grep -o '[0-9]*')
        npx snarkjs powersoftau new bn128 "$POT_N" "${POT%.ptau}_0000.ptau" -v
        npx snarkjs powersoftau contribute \
            "${POT%.ptau}_0000.ptau" "${POT%.ptau}_0001.ptau" \
            --name="snap-depth${DEPTH}" -e="$(openssl rand -hex 32)" -v
        npx snarkjs powersoftau prepare phase2 \
            "${POT%.ptau}_0001.ptau" "$POT" -v
        rm "${POT%.ptau}_0000.ptau" "${POT%.ptau}_0001.ptau"
        ok "Generated $POT"
    else
        ok "Using existing $POT"
    fi

    # ------------------------------------------------------------------
    # 4. Generate zkey (skip if already done)
    # ------------------------------------------------------------------
    ZKEY="$D_DIR/zkey_d${DEPTH}_final.zkey"
    if [ ! -f "$ZKEY" ]; then
        log "Generating zkey (Phase 2 setup, ~15 min on RPi 4)..."
        npx snarkjs groth16 setup \
            "$D_DIR/ulp_auth_d${DEPTH}.r1cs" "$POT" \
            "$D_DIR/zkey_d${DEPTH}_0000.zkey"
        npx snarkjs zkey contribute \
            "$D_DIR/zkey_d${DEPTH}_0000.zkey" "$ZKEY" \
            --name="snap-depth${DEPTH}" -e="$(openssl rand -hex 32)" -v
        rm "$D_DIR/zkey_d${DEPTH}_0000.zkey"
        ok "zkey ready: $ZKEY"
    else
        ok "zkey already exists, skipping."
    fi

    # ------------------------------------------------------------------
    # 5. Generate input.json for this depth
    # ------------------------------------------------------------------
    INPUT_JSON="$D_DIR/input.json"
    if [ ! -f "$INPUT_JSON" ]; then
        log "Generating input.json..."
        gen_input "$INPUT_JSON" "$DEPTH"
        ok "Input ready"
    else
        ok "input.json exists, skipping."
    fi

    # ------------------------------------------------------------------
    # 6. Benchmark: N_WARMUP warmup + N_RUNS measured runs
    # ------------------------------------------------------------------
    WASM="$D_DIR/ulp_auth_d${DEPTH}_js/ulp_auth_d${DEPTH}.wasm"
    DEPTH_OUT="results/bench_depth${DEPTH}.json"

    log "Benchmarking depth-${DEPTH} (${N_WARMUP} warmup + ${N_RUNS} runs)..."
    run_bench "$DEPTH_OUT" "$DEPTH" "$WASM" "$ZKEY" "$INPUT_JSON" "$CONSTRAINTS"
    ok "Results: $DEPTH_OUT"

    DEPTH_JSON_FILES+=("$DEPTH_OUT")
done

# -------------------------------------------------------
# 7. Combine all depth results into one JSON
# -------------------------------------------------------
log "Combining results..."

# Detect hardware
if [ -f /proc/cpuinfo ]; then
    HW=$(grep "^Model" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs || \
         grep "^Hardware" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs || \
         echo "Linux/ARM")
else
    HW="$(uname -s)/$(uname -m)"
fi

node -e "
const fs = require('fs');
const files = $(printf '"%s",' "${DEPTH_JSON_FILES[@]}" | sed 's/,$//' | sed 's/^/[/' | sed 's/$/]/');
const depths = files.map(f => JSON.parse(fs.readFileSync(f)));
const out = {
    benchmark:  'prove_time_vs_merkle_depth',
    hardware:   '${HW}',
    prover:     'rapidsnark',
    circuit:    'ULP_V2V_Auth (BN254)',
    timestamp:  new Date().toISOString(),
    depths,
};
fs.writeFileSync('${OUT_JSON}', JSON.stringify(out, null, 2));
console.log('');
console.log('='.repeat(56));
console.log('  Depth Scaling Benchmark — Summary');
console.log('='.repeat(56));
depths.forEach(d => {
    console.log('  depth-' + String(d.depth).padEnd(3) +
        ' (' + String(d.num_leaves).padStart(6) + ' leaves) : ' +
        d.prove_mean_ms.toFixed(1).padStart(8) + ' ms  ± ' +
        d.prove_std_ms.toFixed(1) + ' ms');
});
console.log('='.repeat(56));
console.log('  Output: ${OUT_JSON}');
"

echo ""
ok "Done! Results in ${OUT_JSON}"
