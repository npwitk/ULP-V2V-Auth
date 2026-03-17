#!/bin/bash
# =============================================================================
# install_rapidsnark.sh
#
# Builds and installs rapidsnark (native C++ BN254 Groth16 prover) on the
# current machine. Works on ARM64 (Raspberry Pi 4) and x86_64 (Mac/Linux).
#
# After installation, the binary is at: /usr/local/bin/rapidsnark
#
# Runtime:
#   RPi 4 (ARM Cortex-A72)  : ~15–25 min  (Rust not needed; pure C++/CMake)
#   Mac (Apple Silicon)     : ~3–5 min
#
# Run: bash scripts/install_rapidsnark.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${BLUE}[rapidsnark]${NC} $1"; }
ok()   { echo -e "${GREEN}[ok]${NC}    $1"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $1"; }
err()  { echo -e "${RED}[error]${NC} $1"; }

INSTALL_DIR="$HOME/rapidsnark"
INSTALL_PREFIX="/usr/local"

# ================================================================
# Step 1: System dependencies
# ================================================================
log "Step 1/5 — Installing system dependencies..."

if [[ "$(uname)" == "Darwin" ]]; then
    # macOS
    if ! command -v brew &>/dev/null; then
        err "Homebrew not found. Install from https://brew.sh first."
        exit 1
    fi
    brew install cmake gmp nlohmann-json nasm
    ok "macOS dependencies installed."
elif [[ "$(uname)" == "Linux" ]]; then
    # Debian/Raspberry Pi OS
    sudo apt-get update -qq
    sudo apt-get install -y \
        cmake build-essential \
        libgmp-dev libsodium-dev \
        nasm nlohmann-json3-dev \
        git
    ok "Linux dependencies installed."
else
    err "Unsupported OS: $(uname)"
    exit 1
fi

# ================================================================
# Step 2: Clone rapidsnark
# ================================================================
log "Step 2/5 — Cloning rapidsnark..."

if [ -d "$INSTALL_DIR" ]; then
    warn "Directory $INSTALL_DIR already exists — pulling latest."
    cd "$INSTALL_DIR"
    git pull
else
    git clone https://github.com/iden3/rapidsnark.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

git submodule init
git submodule update
ok "Repository ready."

# ================================================================
# Step 3: Build GMP (for non-x86 — required on ARM64)
# ================================================================
ARCH=$(uname -m)
log "Step 3/5 — Building GMP for $ARCH..."

if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    log "ARM64 detected — building portable GMP (no x86 assembly)."
    ./build_gmp.sh host
    ok "GMP built for ARM64."
else
    log "x86_64 detected — using system GMP."
fi

# ================================================================
# Step 4: CMake build
# ================================================================
log "Step 4/5 — Building rapidsnark (this takes a while on RPi)..."

BUILD_DIR="$INSTALL_DIR/build_prover"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# -DUSE_ASM=NO is safe for ARM (avoids x86 asm); ignored silently on x86
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
    -DUSE_ASM=NO 2>/dev/null || \
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"

make -j"$(nproc)"
ok "Build complete."

# ================================================================
# Step 5: Install binary
# ================================================================
log "Step 5/5 — Installing binary to $INSTALL_PREFIX/bin/rapidsnark..."
sudo make install

# Verify
if command -v rapidsnark &>/dev/null; then
    ok "rapidsnark installed: $(which rapidsnark)"
else
    # Fallback: binary may be in build dir
    BINARY=$(find "$BUILD_DIR" -name "prover" -o -name "rapidsnark" 2>/dev/null | head -1)
    if [ -n "$BINARY" ]; then
        sudo cp "$BINARY" "$INSTALL_PREFIX/bin/rapidsnark"
        ok "Installed from build dir: $BINARY → $INSTALL_PREFIX/bin/rapidsnark"
    else
        err "Binary not found after build. Check $BUILD_DIR manually."
        exit 1
    fi
fi

echo ""
echo "=============================================="
echo "  rapidsnark ready!"
echo "  Binary : $(which rapidsnark)"
echo "  Usage  : rapidsnark <zkey> <witness.wtns> <proof.json> <public.json>"
echo ""
echo "  Run benchmark:"
echo "    npm run bench-rapid"
echo "=============================================="
