#!/bin/bash
# =============================================================================
# setup.sh — One-time trusted setup for ULP-V2V-Auth
#
# What this does:
#   1. Compiles the Circom circuit to R1CS + WASM
#   2. Downloads Powers of Tau (Phase 1, universal, from Hermez)
#   3. Runs Phase 2 (circuit-specific Groth16 setup)
#   4. Exports the verification key
#
# Requirements (install before running):
#   - circom:   cargo install circom  OR  https://docs.circom.io/getting-started/installation/
#   - snarkjs:  npm install  (installs from package.json)
#   - node >= 18
#
# Runtime:   ~3–8 min on Apple Silicon (M-series Mac)
# Disk use:  ~150 MB for pot12 + ~30 MB for keys
# =============================================================================

set -euo pipefail

CIRCUIT_NAME="ulp_v2v_auth"
BUILD_DIR="./build"
KEYS_DIR="./keys"
CIRCUIT_FILE="circuits/${CIRCUIT_NAME}.circom"

# ---- Colours ----
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[setup]${NC} $1"; }
ok()  { echo -e "${GREEN}[ok]${NC}    $1"; }

mkdir -p "$BUILD_DIR" "$KEYS_DIR"

# ================================================================
# Step 1: Compile circuit
# ================================================================
log "Step 1/5 — Compiling circuit (depth=8, ~2600 constraints)..."
circom "$CIRCUIT_FILE" \
  --r1cs --wasm --sym \
  -o "$BUILD_DIR" \
  -l node_modules

ok "Circuit compiled → ${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"

# Print constraint count
npx snarkjs r1cs info "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"

# ================================================================
# Step 2: Download Powers of Tau (pot12 = 4096 constraints max)
# ================================================================
PTAU_FILE="${BUILD_DIR}/pot12_final.ptau"

if [ -f "$PTAU_FILE" ]; then
    ok "pot12 already downloaded, skipping."
else
    log "Step 2/5 — Downloading Powers of Tau (pot12, ~128 MB)..."
    curl -L -o "$PTAU_FILE" \
      "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau"
    ok "Downloaded → $PTAU_FILE"
fi

# ================================================================
# Step 3: Groth16 Phase 2 setup (circuit-specific)
# ================================================================
log "Step 3/5 — Groth16 Phase 2 setup..."
npx snarkjs groth16 setup \
  "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" \
  "$PTAU_FILE" \
  "${KEYS_DIR}/${CIRCUIT_NAME}_0000.zkey"
ok "Phase 2 initialised."

# ================================================================
# Step 4: Contribute randomness (simulated single-party contribution)
# ================================================================
log "Step 4/5 — Contributing randomness to Phase 2..."
ENTROPY=$(openssl rand -hex 32)
npx snarkjs zkey contribute \
  "${KEYS_DIR}/${CIRCUIT_NAME}_0000.zkey" \
  "${KEYS_DIR}/${CIRCUIT_NAME}_final.zkey" \
  --name="ULP-V2V-Auth Research Contribution" \
  -v \
  -e="$ENTROPY"

# Clean up intermediate key
rm "${KEYS_DIR}/${CIRCUIT_NAME}_0000.zkey"
ok "Final proving key → ${KEYS_DIR}/${CIRCUIT_NAME}_final.zkey"

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
echo "  Setup complete! Next steps:"
echo "    npm run gen-input   # generate test input"
echo "    npm run prove       # prove + verify once"
echo "    npm run bench       # latency benchmark"
echo "    npm run bench-batch # batch verification"
echo "=============================================="
