# ULP-V2V-Auth

**Ultra-Low-Latency Privacy-Preserving V2V Authentication Using Zero-Knowledge Proofs**

---

## What This Implements

A full end-to-end prototype of ULP-V2V-Auth across all four protocol phases:

| Phase | Description                                          | Where                                           |
| ----- | ---------------------------------------------------- | ----------------------------------------------- |
| 1     | Vehicle registration with Trusted Authority (TA)     | `server/ta_server.js`, `obu/register.js`        |
| 2     | Anonymous Session Token (AST) acquisition from AIS   | `server/ais_server.js`, `obu/acquire_ast.js`    |
| 3     | Offline ZK proof precomputation + online BSM binding | `benchmark/bench_prover.js`, `obu/bench_e2e.js` |
| 4     | Groth16 batch verification at receiver               | `benchmark/bench_batch_verify.js`               |

The Groth16 circuit proves three things simultaneously:

1. The vehicle holds a valid **Anonymous Session Token (AST)** included in the Merkle tree
2. The current timestamp is within the AST's **validity window** `[t_start, t_end]`
3. The **message hash** `h_m = Poseidon(m, t_current)` binds the proof to a specific BSM

---

## Project Structure

```
ULP-V2V-Auth/
├── circuits/
│   └── ulp_v2v_auth.circom        # Groth16 circuit (~5,586 constraints, depth=8)
├── scripts/
│   ├── setup.sh                   # Trusted setup (run once)
│   ├── gen_input.js               # Build test Merkle tree + write input.json
│   └── prove_and_verify.js        # Single prove + verify with timing
├── server/
│   ├── ta_server.js               # Trusted Authority server (port 3001)
│   └── ais_server.js              # AST Issuing Service server (port 3002)
├── obu/
│   ├── register.js                # Vehicle registration client (Phase 1)
│   ├── acquire_ast.js             # AST acquisition client (Phase 2)
│   └── bench_e2e.js               # End-to-end latency budget benchmark
├── benchmark/
│   ├── bench_prover.js            # Prover latency (N-run mean/std)
│   ├── bench_batch_verify.js      # Sequential vs batch verification at k=1..30
│   ├── bench_pairing_breakdown.js # Miller loop + final exp breakdown
│   ├── bench_poseidon.js          # Poseidon-2 online binding cost
│   ├── bench_rapidsnark.js        # rapidsnark vs snarkjs prover comparison
│   ├── bench_ecdsa_baseline.js    # ECDSA-P256 baseline (IEEE 1609.2 comparison)
│   ├── groth16_batch_verify.js    # True Groth16 batch verifier (k+3 pairings)
│   └── plot_results.py            # Matplotlib figures for paper
├── latex/
│   ├── main.tex                   # Master LaTeX file (\input each section)
│   ├── refs.bib                   # BibTeX bibliography (24 entries)
│   └── sections/                  # One .tex file per paper section
├── build/                         # Compiled circuit outputs (git-ignored)
├── keys/                          # Proving + verification keys (git-ignored)
└── results/                       # Benchmark JSON data
```

---

## Hardware Setup (Full Testbed)

```
[Mac]                              [Wi-Fi / LAN]
  npm run ta-server  (port 3001) ──────────────────┐
  npm run ais-server (port 3002)                   │
                                                   │
[Raspberry Pi 1] ──────────────────────────────────┤
  VIN001 — register, acquire_ast, benchmarks       │
                                                   │
[Raspberry Pi 2] ──────────────────────────────────┘
  VIN002 — register, acquire_ast, benchmarks
```

The Mac acts as infrastructure (TA + AIS). The RPis are the OBUs doing real-time ZKP work.
All benchmark scripts except `bench_e2e.js` run fully locally — no network required.

---

## Prerequisites

### 1. Install circom

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
git clone https://github.com/iden3/circom.git
cd circom && cargo build --release && cargo install --path circom && cd ..
```

Verify: `circom --version` → `circom compiler 2.x.x`

### 2. Install Node.js dependencies

```bash
npm install
```

### 3. Python (for plotting only)

```bash
pip3 install matplotlib numpy
```

---

## Quick Start

### Step 1: Trusted Setup (run once, ~5–10 min)

```bash
npm run setup
```

Compiles the circuit (~5,586 constraints), runs Powers of Tau (pot13) locally, and exports keys to `keys/`.

### Step 2: Generate Test Input

```bash
npm run gen-input
```

Builds a depth-8 Poseidon Merkle tree of 256 AST leaves and writes `build/input.json`.

### Step 3: Single Prove + Verify

```bash
npm run prove
```

---

## Running the Full Testbed (Phases 1–4)

### On Mac — start servers

```bash
# Terminal 1
npm run ta-server          # TA on port 3001

# Terminal 2
npm run ais-server         # AIS on port 3002
```

Find your Mac's LAN IP: `ipconfig getifaddr en0`

### On each RPi — register and acquire AST

```bash
node obu/register.js    --ta=http://MAC_IP:3001 --vin=VIN001
node obu/acquire_ast.js --ais=http://MAC_IP:3002
```

This writes `obu_data/identity.json`, `obu_data/ast.json`, and `build/input.json`.

---

## Benchmarks

All benchmarks save JSON results to `results/`. Run on RPi 4 for paper data.

| Script                                           | What it measures                              | Network?      |
| ------------------------------------------------ | --------------------------------------------- | ------------- |
| `npm run bench`                                  | Prover latency — fullProve mean/std (20 runs) | No            |
| `npm run bench-batch`                            | Sequential vs batch verify at k=1,5,10,30     | No            |
| `npm run bench-pairing`                          | Miller loop + final exp breakdown             | No            |
| `npm run bench-poseidon`                         | Poseidon-2 online binding cost per call       | No            |
| `npm run bench-rapid`                            | rapidsnark C++ vs snarkjs prover              | No            |
| `npm run bench-ecdsa`                            | ECDSA-P256 sign/verify vs ZKP baseline        | No            |
| `node obu/bench_e2e.js --ais=http://MAC_IP:3002` | Full end-to-end latency budget (Phases 2–4)   | Phase 2a only |

### Recommended run order on RPi

```bash
npm run bench-poseidon    # ~1 min  — proves 0.377 ms online binding headline
npm run bench-batch       # ~5 min  — proves 4.54× batch speedup at k=30
npm run bench-ecdsa       # ~2 min  — ECDSA baseline comparison
node obu/bench_e2e.js --ais=http://MAC_IP:3002   # requires TA+AIS running on Mac
npm run bench             # ~10 min — prover latency (2,355 ms snarkjs)
npm run bench-rapid       # ~5 min  — rapidsnark 976 ms comparison
npm run bench-pairing     # ~3 min  — pairing breakdown
```

Generate paper figures after running:

```bash
npm run plot
```

---

## Scaling to Depth-16 (Full System)

The paper's full system uses a depth-16 Merkle tree (65,536 AST leaves).

1. Edit `circuits/ulp_v2v_auth.circom` last line: `ULP_V2V_Auth(8)` → `ULP_V2V_Auth(16)`
2. Edit `scripts/setup.sh`: `pot13` → `pot17`
3. Edit `scripts/gen_input.js`: `DEPTH = 8` → `DEPTH = 16`
4. Rebuild:
   ```bash
   rm -rf build/ keys/
   npm run setup && npm run gen-input && npm run bench
   ```

> pot17 generation takes 30–60 min and ~2 GB RAM. Run on RPi directly.

---

## Key Numbers (RPi 4, depth-8)

| Metric                              | Value      |
| ----------------------------------- | ---------- |
| Online binding (Poseidon-2)         | 0.377 ms   |
| Offline precomputation (snarkjs)    | 2,355 ms   |
| Offline precomputation (rapidsnark) | 976 ms     |
| Batch verify k=30                   | ~378 ms    |
| Batch speedup at k=30               | 4.54×      |
| Proof size (BN254)                  | ~128 bytes |

---

## Mapping to Paper Claims

| Paper Claim                                | Benchmark          |
| ------------------------------------------ | ------------------ |
| 0.377 ms online binding cost               | `bench-poseidon`   |
| 4.54× batch verification speedup at k=30   | `bench-batch`      |
| 976 ms offline precomputation (rapidsnark) | `bench-rapid`      |
| ECDSA-P256 sign/verify comparison          | `bench-ecdsa`      |
| End-to-end latency budget table            | `obu/bench_e2e.js` |
| ~128 byte proof size                       | `prove`            |
