# ULP-V2V-Auth

**Ultra-Low-Latency Privacy-Preserving V2V Authentication Using Zero-Knowledge Proofs**

A full prototype of the ULP-V2V-Auth protocol — a Groth16 zk-SNARK scheme for anonymous, unlinkable vehicle-to-vehicle authentication that fits within the 100 ms BSM broadcast window.

---

## What This Implements

Four protocol phases, end-to-end:

| Phase | Description                                          | Where                                           |
| ----- | ---------------------------------------------------- | ----------------------------------------------- |
| 1     | Vehicle registration with Trusted Authority (TA)     | `server/ta_server.js`, `obu/register.js`        |
| 2     | Anonymous Session Token (AST) acquisition from AIS   | `server/ais_server.js`, `obu/acquire_ast.js`    |
| 3     | Offline ZK proof precomputation + online BSM signing | `benchmark/bench_prover.js`, `obu/bench_e2e.js` |
| 4     | Groth16 batch verification + DCV fallback            | `benchmark/bench_batch_verify.js`, `bench_dcv.js` |

The Groth16 circuit (`circuits/ulp_v2v_auth.circom`) proves three things simultaneously:

1. The vehicle holds a valid **AST** whose leaf is included in the Merkle tree
2. The current timestamp is within the AST's **validity window** `[t_start, t_end]`
3. The **one-time public key** `pk_ot` is bound to this proof via Groth16's IC vector

Message binding is done outside the circuit: the sender signs `(m ‖ t_current)` with `sk_ot`; the receiver checks the ECDSA-P256 signature under `pk_ot`.

---

## Source Code Overview

```
ULP-V2V-Auth/
├── circuits/
│   └── ulp_v2v_auth.circom        # Groth16 circuit (~5,800 constraints, depth=8)
│
├── scripts/
│   ├── setup.sh                   # Trusted setup: compile → Powers of Tau → zkey export
│   ├── gen_input.js               # Build Poseidon Merkle tree + write build/input.json
│   └── prove_and_verify.js        # Single prove + verify cycle with timing printout
│
├── server/
│   ├── ta_server.js               # Trusted Authority (port 3001) — Phase 1
│   └── ais_server.js              # AST Issuing Service (port 3002) — Phase 2
│
├── obu/
│   ├── register.js                # Vehicle registration client (Phase 1)
│   ├── acquire_ast.js             # AST acquisition client (Phase 2)
│   └── bench_e2e.js               # End-to-end latency budget (Phases 2–4)
│
├── benchmark/
│   ├── bench_prover.js            # Prover latency: snarkjs fullProve mean/std (20 runs)
│   ├── bench_batch_verify.js      # Sequential vs Groth16 batch verify at k=1..30
│   ├── bench_pairing_breakdown.js # Miller loop + final exponentiation breakdown
│   ├── bench_poseidon.js          # Poseidon-2 online binding cost (the 0.377 ms headline)
│   ├── bench_rapidsnark.js        # rapidsnark C++ vs snarkjs prover comparison
│   ├── bench_ecdsa_baseline.js    # ECDSA-P256 sign/verify baseline (IEEE 1609.2)
│   ├── bench_wu_clss.js           # Wu et al. CLSS (4×G1mult+2×G1add) sender cost
│   ├── bench_comparison.js        # Head-to-head: SCMS vs Wu et al. vs ULP (all 3 sections)
│   ├── bench_raba.js              # RABA adaptive batch auth under 4 traffic densities
│   ├── bench_raba_ablation.js     # Ablation: adaptive-k vs fixed-k, per-class vs global DCV
│   ├── bench_dcv.js               # DCV fallback (Algorithm 4): w=1 and w=3 adversarial
│   ├── bench_primitives.js        # Individual primitive costs (Poseidon, pairing, G1 mult)
│   ├── bench_proof_cache.js       # Proof slot cache hit/miss cost analysis
│   ├── bench_jiang_lattice.js     # Jiang & Guo lattice scheme comparison
│   ├── groth16_batch_verify.js    # True Groth16 batch verifier (k+3 pairings)
│   └── plot_results.py            # Matplotlib figures for paper (PDF output)
│
├── build/                         # Compiled circuit + witness generator (git-ignored)
├── keys/                          # Proving key + verification key (git-ignored)
└── results/                       # Benchmark JSON output files
```

---

## Prerequisites

### 1. Node.js ≥ 18

```bash
node --version   # must be ≥ 18.0.0
```

### 2. circom compiler (from source)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
git clone https://github.com/iden3/circom.git
cd circom && cargo build --release && cargo install --path circom && cd ..
circom --version   # → circom compiler 2.x.x
```

### 3. Node.js dependencies

```bash
npm install
```

This installs: `snarkjs`, `circomlib`, `circomlibjs`, `ffjavascript`, `express`, `ws`.

### 4. Python (for plotting only)

```bash
pip3 install matplotlib numpy
```

### 5. rapidsnark (optional — for `bench-rapid` only)

```bash
npm run install-rapidsnark
```

Builds the native C++ prover from source. Requires `cmake`, `g++`, and `libgmp-dev`.

---

## Installation & Setup

### Step 1: Trusted Setup (run once, ~5–10 min)

```bash
npm run setup
```

What this does:
1. Compiles `circuits/ulp_v2v_auth.circom` → R1CS + WASM witness generator (`build/`)
2. Generates Powers of Tau `pot13` locally (supports up to 8192 constraints)
3. Runs Groth16 Phase 2 ceremony → `keys/ulp_v2v_auth_final.zkey`
4. Exports the verification key → `keys/verification_key.json`

Expected output files after setup:
```
build/ulp_v2v_auth.r1cs
build/ulp_v2v_auth_js/ulp_v2v_auth.wasm
build/pot13_final.ptau
keys/ulp_v2v_auth_final.zkey
keys/verification_key.json
```

### Step 2: Generate Test Input

```bash
npm run gen-input
```

Builds a depth-8 Poseidon Merkle tree of 256 simulated AST leaves, picks leaf index 3, generates the Merkle inclusion proof, and writes:

```
build/input.json      ← circuit input (public + private signals)
build/tree_meta.json  ← tree parameters
```

### Step 3: Single Prove + Verify (correctness check)

```bash
npm run prove
```

Runs one full Groth16 `fullProve` + `verify` cycle. Prints prove time, verify time, proof size, and saves `build/proof.json` + `build/public.json` for use by batch benchmarks.

---

## Running the Full Protocol Testbed (Phases 1–4)

This requires a Mac (acting as TA + AIS) and one or two Raspberry Pi 4 boards (acting as OBUs). All benchmark scripts can also run locally on the Mac.

### On Mac — start the servers

```bash
# Terminal 1: Trusted Authority
npm run ta-server          # listens on port 3001

# Terminal 2: AST Issuing Service
npm run ais-server         # listens on port 3002 (connects to TA at 127.0.0.1:3001)
```

Find the Mac's LAN IP:
```bash
ipconfig getifaddr en0
```

### On each Raspberry Pi — register and acquire AST

```bash
# Phase 1: vehicle registration
node obu/register.js --ta=http://MAC_IP:3001 --vin=VIN001

# Phase 2: AST acquisition
node obu/acquire_ast.js --ais=http://MAC_IP:3002
```

This creates `obu_data/identity.json`, `obu_data/ast.json`, and `build/input.json`.

### End-to-end latency test (requires servers running)

```bash
node obu/bench_e2e.js --ais=http://MAC_IP:3002
```

Measures the full Phase 2–4 latency budget and prints a breakdown table.

---

## Running the Benchmarks

All benchmark scripts require `npm run setup && npm run gen-input` first. Results are saved as JSON in `results/`.

### Quick benchmark table

| npm script              | Script                            | What it measures                               | Network? | Time (RPi 4) |
| ----------------------- | --------------------------------- | ---------------------------------------------- | -------- | ------------ |
| `npm run prove`         | `scripts/prove_and_verify.js`     | Single prove + verify + proof size             | No       | ~2.4 s       |
| `npm run bench`         | `benchmark/bench_prover.js`       | Prover latency mean/std (20 runs, snarkjs)     | No       | ~10 min      |
| `npm run bench-batch`   | `benchmark/bench_batch_verify.js` | Sequential vs batch verify at k=1,5,10,20,30  | No       | ~5 min       |
| `npm run bench-poseidon`| `benchmark/bench_poseidon.js`     | Poseidon-2 online binding cost (0.377 ms)      | No       | ~1 min       |
| `npm run bench-ecdsa`   | `benchmark/bench_ecdsa_baseline.js` | ECDSA-P256 sign/verify vs ZKP baseline       | No       | ~2 min       |
| `npm run bench-rapid`   | `benchmark/bench_rapidsnark.js`   | rapidsnark C++ vs snarkjs prover               | No       | ~5 min       |
| `npm run bench-pairing` | `benchmark/bench_pairing_breakdown.js` | Miller loop + final exponentiation        | No       | ~3 min       |
| `npm run bench-comparison` | `benchmark/bench_comparison.js` | SCMS vs Wu et al. vs ULP (Sections A/B/C)   | No       | ~20 min      |
| `npm run bench-raba`    | `benchmark/bench_raba.js`         | RABA adaptive batch auth (4 traffic densities) | No       | ~30 min      |
| `npm run bench-ablation`| `benchmark/bench_raba_ablation.js`| Adaptive-k vs fixed-k; per-class vs global DCV | No      | ~15 min      |
| `npm run bench-dcv`     | `benchmark/bench_dcv.js`          | DCV fallback: w=1 and w=3 adversarial          | No       | ~10 min      |
| `npm run bench-cache`   | `benchmark/bench_proof_cache.js`  | Proof slot cache hit/miss cost                 | No       | ~5 min       |
| `npm run bench-primitives` | `benchmark/bench_primitives.js` | Individual primitive costs breakdown          | No       | ~3 min       |
| `node obu/bench_e2e.js --ais=http://MAC_IP:3002` | `obu/bench_e2e.js` | Full E2E latency budget (Phases 2–4) | Phase 2 only | ~2 min |

### Recommended run order on RPi 4 (for paper data)

```bash
# 1. Core single-proof numbers
npm run bench-poseidon      # 0.377 ms Poseidon-2 online binding
npm run bench-ecdsa         # ECDSA-P256 baseline comparison

# 2. Batch verification speedup
npm run bench-batch         # 4.54× speedup at k=30

# 3. Head-to-head scheme comparison (Sections A/B/C)
npm run bench-comparison    # SCMS vs Wu et al. vs ULP

# 4. Prover latency
npm run bench               # snarkjs: ~2,355 ms
npm run bench-rapid         # rapidsnark: ~976 ms

# 5. Phase 4 algorithms
npm run bench-dcv           # DCV fallback: call-count vs theoretical bound
npm run bench-raba          # RABA under free-flow / moderate / dense / dense+adversarial
npm run bench-ablation      # Ablation: adaptive-k and per-class DCV

# 6. Additional analysis
npm run bench-pairing       # Miller loop + final exp breakdown
npm run bench-cache         # Proof slot cache analysis

# 7. Generate figures
npm run plot
```

---

## Generating Paper Figures

After running benchmarks, generate all PDF figures:

```bash
npm run plot
```

This reads `results/*.json` and produces figures in `results/`:
- `fig_batch_verify.pdf` — batch verification speedup curve
- `fig_prover_latency.pdf` — prover latency distribution

---

## Testing / Verifying Correctness

### Minimal correctness test (no hardware required)

```bash
npm run setup        # ~5–10 min
npm run gen-input
npm run prove        # must print: Valid : ✓ YES
```

### Verify DCV call counts match theoretical bounds

```bash
npm run bench-dcv
```

The output prints `✓ PASS` or `✗ FAIL` for both the w=1 and w=3 adversarial cases, comparing actual DCV call counts against the theoretical bound `2w⌈log₂(k/w)⌉`.

### Verify batch verifier is correct

```bash
npm run bench-batch
```

At k=1, the batch result must match individual `snarkjs.groth16.verify`. The speedup at k=30 should be approximately 4×–5×.

---

## Scaling to Depth-16 (Metro-Scale)

The depth-8 circuit supports 256 simultaneous ASTs (highway segments). For metro-scale (65,536 ASTs):

1. Edit `circuits/ulp_v2v_auth.circom` last line: `ULP_V2V_Auth(8)` → `ULP_V2V_Auth(16)`
2. Edit `scripts/setup.sh`: `pot13` → `pot17`
3. Edit `scripts/gen_input.js`: `DEPTH = 8` → `DEPTH = 16`
4. Rebuild:
   ```bash
   rm -rf build/ keys/
   npm run setup && npm run gen-input
   ```

> `pot17` generation requires ~2 GB RAM and 30–60 min. Run directly on the RPi.

---

## Hardware Testbed Layout

```
[Mac]                               [Wi-Fi / LAN]
  npm run ta-server  (port 3001) ───────────────────┐
  npm run ais-server (port 3002)                    │
                                                    │
[Raspberry Pi 4 — OBU 1] ─────────────────────────┤
  VIN001: register → acquire_ast → benchmarks       │
                                                    │
[Raspberry Pi 4 — OBU 2] ─────────────────────────┘
  VIN002: register → acquire_ast → benchmarks
```

All benchmark scripts except `obu/bench_e2e.js` run fully offline — no network needed.

---

## Key Results (RPi 4, depth-8)

| Metric                                       | Value       |
| -------------------------------------------- | ----------- |
| Online binding cost (Poseidon-2)             | 0.377 ms    |
| Offline precomputation (snarkjs)             | ~2,355 ms   |
| Offline precomputation (rapidsnark)          | ~976 ms     |
| Batch verify k=30 (true Groth16 batch)       | ~378 ms     |
| Batch speedup vs sequential at k=30          | ~4.54×      |
| DCV fallback calls at w=1 (k=30)             | ≤ 10        |
| Proof size (BN254, compressed)               | ~128 bytes  |
| Circuit size (depth=8)                       | ~5,800 R1CS constraints |

---

## Mapping to Paper Claims

| Paper Claim                                    | Benchmark script        |
| ---------------------------------------------- | ----------------------- |
| 0.377 ms online binding cost                   | `bench-poseidon`        |
| 4.54× batch verification speedup at k=30       | `bench-batch`           |
| 976 ms offline precomputation (rapidsnark)     | `bench-rapid`           |
| ECDSA-P256 sign/verify comparison              | `bench-ecdsa`           |
| Head-to-head vs SCMS and Wu et al.             | `bench-comparison`      |
| RABA deadline compliance under 4 densities     | `bench-raba`            |
| DCV call count ≤ 2w⌈log₂(k/w)⌉               | `bench-dcv`             |
| Adaptive-k and per-class DCV ablation          | `bench-ablation`        |
| End-to-end latency budget table                | `obu/bench_e2e.js`      |
| ~128 byte proof size                           | `npm run prove`         |
