#!/bin/bash
# =============================================================================
# setup.sh — One-time trusted setup for ULP-V2V-Auth
#
# Circuit has ~5586 constraints → requires pot13 (2^13 = 8192 max).
# We generate the Powers of Tau locally — no external downloads needed.
#
# Runtime:   ~5–10 min on Apple Silicon
# Disk use:  ~50 MB
# =============================================================================

set -euo pipefail

CIRCUIT_NAME="ulp_v2v_auth"
BUILD_DIR="./build"
KEYS_DIR="./keys"
CIRCUIT_FILE="circuits/${CIRCUIT_NAME}.circom"
PTAU_FILE="${BUILD_DIR}/pot13_final.ptau"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${BLUE}[setup]${NC} $1"; }
ok()   { echo -e "${GREEN}[ok]${NC}    $1"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $1"; }

mkdir -p "$BUILD_DIR" "$KEYS_DIR"

# ================================================================
# Step 1: Compile circuit
# ================================================================
log "Step 1/5 — Compiling circuit..."
circom "$CIRCUIT_FILE" \
  --r1cs --wasm --sym \
  -o "$BUILD_DIR" \
  -l ./node_modules

ok "Circuit compiled → ${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"
npx snarkjs r1cs info "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"

# ================================================================
# Step 2: Powers of Tau — pot13 (supports up to 8192 constraints)
# ================================================================
if [ -f "$PTAU_FILE" ]; then
    ok "pot13 already exists, skipping generation."
else
    log "Step 2/5 — Generating Powers of Tau pot13 locally (~5 min)..."
    warn "No download needed — local generation is valid for research prototypes."

    npx snarkjs powersoftau new bn128 13 \
      "${BUILD_DIR}/pot13_0000.ptau" -v

    npx snarkjs powersoftau contribute \
      "${BUILD_DIR}/pot13_0000.ptau" \
      "${BUILD_DIR}/pot13_0001.ptau" \
      --name="ULP-V2V-Auth-Phase1" -v \
      -e="$(openssl rand -hex 64)"

    npx snarkjs powersoftau prepare phase2 \
      "${BUILD_DIR}/pot13_0001.ptau" \
      "$PTAU_FILE" -v

    rm "${BUILD_DIR}/pot13_0000.ptau" "${BUILD_DIR}/pot13_0001.ptau"
    ok "Powers of Tau ready → $PTAU_FILE"
fi

# ================================================================
# Step 3: Groth16 Phase 2 setup (circuit-specific zkey)
# ================================================================
log "Step 3/5 — Groth16 Phase 2 setup..."
npx snarkjs groth16 setup \
  "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" \
  "$PTAU_FILE" \
  "${KEYS_DIR}/${CIRCUIT_NAME}_0000.zkey"
ok "Phase 2 initialised."

# ================================================================
# Step 4: Contribute randomness to Phase 2
# ================================================================
log "Step 4/5 — Contributing randomness to Phase 2..."
npx snarkjs zkey contribute \
  "${KEYS_DIR}/${CIRCUIT_NAME}_0000.zkey" \
  "${KEYS_DIR}/${CIRCUIT_NAME}_final.zkey" \
  --name="ULP-V2V-Auth-Phase2" -v \
  -e="$(openssl rand -hex 64)"

rm "${KEYS_DIR}/${CIRCUIT_NAME}_0000.zkey"
ok "Proving key → ${KEYS_DIR}/${CIRCUIT_NAME}_final.zkey"

# ================================================================
# Step 5: Export verification key
# ================================================================
log "Step 5/5 — Exporting verification key..."
npx snarkjs zkey export verificationkey \
  "${KEYS_DIR}/${CIRCUIT_NAME}_final.zkey" \
  "${KEYS_DIR}/verification_key.json"
ok "Verification key → ${KEYS_DIR}/verification_key.json"

echo ""
echo "=============================================="
echo "  Setup complete!"
echo "    npm run gen-input    # build test Merkle tree"
echo "    npm run prove        # single prove + verify"
echo "    npm run bench        # prover latency (20 runs)"
echo "    npm run bench-batch  # batch verification"
echo "    npm run plot         # generate PDF figures"
echo "=============================================="
