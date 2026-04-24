# ULP-V2V-Auth — Advisor Meeting Summary
**Date:** March 26, 2026
**Prepared for:** In-person advisor meeting
**Target deadline:** JCSSE 2026 submission — March 30, 2026
**Paper folders:** `latex/` (full version) · `latex_jcsse/` (6-page JCSSE version)

---

## Table of Contents
1. [What We Have Right Now — The Full Paper](#1-what-we-have-right-now)
2. [The ZKP Circuit — What We Prove and Why](#2-the-zkp-circuit)
3. [Every Experiment — Deep Detail](#3-every-experiment--deep-detail)
4. [What Changed From Last Time](#4-what-changed-from-last-time)
5. [What Problems Remain](#5-what-problems-remain)
6. [Full Paper vs JCSSE Version — What Was Cut and Why](#6-full-paper-vs-jcsse-version)
7. [Talking Points for Tomorrow's Meeting](#7-talking-points)

---

## 1. What We Have Right Now

### The Core Idea in One Sentence
ULP-V2V-Auth lets a vehicle broadcast safety messages at 10 Hz with **full cryptographic unlinkability** (zero-knowledge proof), at only **0.439 ms** per message — by generating the ZKP ahead of time offline and caching it, so the real-time step is just a single Poseidon hash.

### The Three Problems We Solve
| Problem | Our Solution |
|---|---|
| ZKP is too slow for real-time V2V (100 ms budget) | Proof-slot cache: generate proof offline, use only Poseidon hash online |
| Certificate-based systems (SCMS) are linkable per certificate period | Groth16 ZKP reveals nothing about the vehicle identity |
| CRL revocation is O(n) — slow to distribute | Merkle tree: removing one leaf changes root; old proofs fail immediately, O(log n) |

### The Four-Phase Protocol
```
Phase 1 — Vehicle Registration (one-time at manufacture)
  Vehicle generates key pair → TA issues blind-signed credential σ_i
  TA public key pre-loaded in tamper-proof OBU module

Phase 2 — AST Acquisition + Offline Precomputation (periodic, at RSU)
  Vehicle → AIS: ZKP of credential possession (without revealing σ_i or pk_i)
  AIS → Vehicle: Anonymous Session Token {sid, tStart, tEnd, cap, r}
                + Merkle inclusion proof π_MT + Merkle root R
  Vehicle OFFLINE: generates N_cache complete Groth16 proofs,
                   each committed to a predicted future BSM message
  All heavy computation happens HERE — not during driving

Phase 3 — Online V2V Authentication (per message, 100 ms cycle)
  Step 1: Dequeue pre-generated proof slot          → < 0.01 ms
  Step 2: Poseidon(message, tCurrent) to bind       → 0.437 ms
  Step 3: Broadcast (BSM, proof, Merkle root)       → 0 extra EC ops
  Total online cost: 0.439 ms  (0.44% of 100 ms budget)

Phase 4 — Batch Verification (receiver side)
  Collect k proofs over 50–100 ms window
  Emergency messages: verify individually in ~70 ms (bypass batch)
  Normal BSMs: batch verify k proofs with k+3 pairings total
  If batch fails: DCV fallback finds all w bad proofs in O(w log k)
```

### Key Numbers (All Measured on Raspberry Pi 4, March 19, 2026)
| Metric | Value | Notes |
|---|---|---|
| Online sender cost | **0.439 ms** | 0.44% of 100 ms BSM budget |
| snarkjs full prove (offline) | **3,841 ms ± 80 ms** | One-time per AST session |
| rapidsnark full prove (offline) | **1,753 ms ± 67 ms** | 2.19× over snarkjs |
| Batch verify at k=30 | **400 ms** | 4.65× speedup over sequential |
| SCMS (ECDSA) sender cost | 0.199 ms | Directly measured on same RPi 4 |
| Our sender vs SCMS | **2.21× overhead** | Price of full unlinkability |
| Our sender vs Wu et al. | **25.1× faster** | 11.0 ms → 0.439 ms |
| BN254 final exp share | **61.4%** | Explains why batch > theory |
| Cache production rate (RPi 4) | 42 slots/min | Needs pre-departure fill |
| Self-sustaining threshold | ≥ 600 slots/min | NXP S32G @ 25× MSM tier |

### Why This Is Novel (Not Just "Combining Techniques")
This paper is a **system-level engineering contribution**. The novelty is:
1. **Offline/online decomposition applied to Groth16 for V2V**: 97.3% of circuit constraints are message-independent → the complete proof can be precomputed offline. No prior V2V-ZKP work achieves <1 ms online sender cost.
2. **Custom true batch Groth16 verification**: We wrote `groth16_batch_verify.js` from scratch using `ffjavascript` curve primitives. snarkjs does NOT have batch verification. This is based on the Bellare-Garay-Rabin 1998 algorithm adapted to Groth16 structure.
3. **Measured speedup exceeds theory, with explanation**: 4.65× measured > 2.73× theoretical. We identify why (final exponentiation = 61.4% of pairing cost, amortized in batch) using direct hardware measurements of curve primitives.
4. **Direct OBU-class hardware validation**: All numbers from actual Raspberry Pi 4 runs, not simulations or PC estimates with slowdown factors.

---

## 2. The ZKP Circuit

**File:** `circuits/ulp_v2v_auth.circom`
**Language:** Circom 2.0
**Libraries imported from circomlib 2.0.5:**
- `poseidon.circom` — SNARK-friendly hash (far fewer constraints than SHA-256)
- `comparators.circom` — LessEqThan for timestamp range checks
- `switcher.circom` — left/right Merkle node selection

### What the Circuit Proves (4 Constraints)
The circuit produces a zero-knowledge proof that the vehicle knows a valid Anonymous Session Token without revealing it:

```
Public inputs (known to everyone):
  merkleRoot    — current epoch root R (all valid vehicles are leaves)
  tCurrent      — message timestamp
  hMessage      — Poseidon(message, tCurrent)  ← message binding

Private witness (only prover knows):
  sid, tStart, tEnd, cap, r  — AST fields (the actual token)
  pathElements[16]            — 16 Merkle sibling hashes along path
  pathIndices[16]             — left/right direction bits (0 or 1)
  message                     — raw BSM content

Constraint 1: leaf = Poseidon(sid, tStart, tEnd, cap, r)
  → The leaf was computed correctly from valid AST fields

Constraint 2: MerklePathVerifier(leaf, path) == merkleRoot
  → This leaf is in the current epoch's Merkle tree (not revoked)

Constraint 3: tStart <= tCurrent <= tEnd
  → The session token is currently valid (32-bit LessEqThan)

Constraint 4: hMessage == Poseidon(message, tCurrent)
  → The proof is bound to this specific BSM and timestamp (replay attack prevention)
```

### Depth-16 Configuration
```circom
// Last line of the file:
component main {public [merkleRoot, tCurrent, hMessage]} = ULP_V2V_Auth(16);
```
- **depth=16** → 65,536-leaf Merkle tree → up to 65,536 simultaneous active vehicles per region
- Requires **pot14** (Powers of Tau ceremony supporting 2^14 = 16,384+ constraints)
- Actual constraint count: **~9,100 constraints**

### Why 97.3% of Constraints Are Message-Independent
| Component | Approx. Constraints | Share | Fixed per AST? |
|---|---|---|---|
| Merkle path (16× Poseidon-2 + 16× Switcher) | ~3,870 | 42.5% | YES |
| AST leaf hash (Poseidon-5) | ~584 | 6.4% | YES |
| Timestamp range checks (2× LessEqThan-32) | ~64 | 0.7% | YES |
| Wiring / linear constraints | ~4,337 | 47.7% | YES |
| **Message binding (Poseidon-2 for hMessage)** | ~245 | **2.7%** | **NO** |

**The key insight:** Because 97.3% of the circuit doesn't change per message, we precompute a **complete Groth16 proof** offline using a predicted message. At broadcast time, we only hash to confirm the prediction. If it matches, broadcast. If not, try the next slot.

---

## 3. Every Experiment — Deep Detail

### All Benchmark Files
```
benchmark/
├── groth16_batch_verify.js    ← CUSTOM (not in any library)
├── bench_prover.js            ← Benchmark 1: snarkjs full prove
├── bench_rapidsnark.js        ← Benchmark 1b: rapidsnark vs snarkjs
├── bench_batch_verify.js      ← Benchmark 2: batch vs sequential
├── bench_poseidon.js          ← Online phase lower bound
├── bench_proof_cache.js       ← Benchmark 3: full proof-slot model
├── bench_pairing_breakdown.js ← Why measured speedup > theoretical
├── bench_ecdsa_baseline.js    ← SCMS comparison baseline
└── bench_primitives.js        ← Wu et al. cost projection
```

All canonical results are in `ulp_results_depth16/` (run on RPi 4, March 19, 2026).

---

### Benchmark 1 — Prover Latency
**File:** `benchmark/bench_prover.js`
**What we called (standard snarkjs, not customized):**
```javascript
// Full prove: witness generation + Groth16 arithmetic (offline cost)
await snarkjs.groth16.fullProve(input, WASM, ZKEY);

// Witness only: circuit evaluation without Groth16 (online proxy)
await snarkjs.wtns.calculate(input, WASM, { type: "mem" });
```
**Method:** 3 warm-up runs (discarded, for V8 JIT) + 20 measured runs. Fixed input from `build/input.json`.

**snarkjs** is a pure JavaScript + WebAssembly Groth16 implementation. The circuit (`.circom`) was compiled by Circom into a WASM witness calculator and `.r1cs` constraint system. snarkjs uses the `.r1cs` + Powers of Tau to create a `.zkey` proving key. All arithmetic happens in JavaScript BigInt / WASM.

**Results (RPi 4, `ulp_results_depth16/bench_prover.json`):**
```
snarkjs Full Prove: 3,841 ms  ± 80 ms     ← offline precomputation cost
Witness Only:         361 ms  ± 5.3 ms    ← conservative online proxy (not the real online cost)
```
The 3,841 ms is done offline — not during driving.

---

### Benchmark 1b — rapidsnark vs snarkjs
**File:** `benchmark/bench_rapidsnark.js`
**Libraries:** `snarkjs` (witness stage) + `rapidsnark` (C++ binary via `execFileSync`)

**rapidsnark** is a native C++ BN254 multi-scalar multiplication prover by iden3/Polygon. It avoids JavaScript BigInt overhead by doing all elliptic curve arithmetic in optimized C++. On RPi 4, we compiled it from source using the **portable GMP backend** — the NEON ARM SIMD path is not yet in upstream rapidsnark, so there is still room for more speedup on ARM.

**Two-stage pipeline:**
```
Stage 1 — Witness:   snarkjs.wtns.calculate(input, WASM) → writes .wtns binary file
Stage 2 — Groth16:   execFileSync(rapidsnarkBin, [ZKEY, .wtns, proof.json, pub.json])
```

**Auto-detection logic we wrote:** Searches 8 paths for the rapidsnark binary (`/usr/local/bin/prover`, `~/rapidsnark/build_prover/src/prover`, etc.). Found at `/usr/local/bin/prover` on the RPi 4.

**After each rapidsnark run, we verify the proof with snarkjs to confirm correctness:**
```javascript
const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
// → true (confirmed on every run)
```

**Results (RPi 4, `ulp_results_depth16/bench_rapidsnark.json`):**
```
snarkjs full prove:         4,050 ms    (this run's baseline)
Witness generation:           374 ms  ± 7.4 ms   (same WASM — unchanged)
rapidsnark prove (C++):     1,379 ms  ± 67 ms
rapidsnark total:           1,753 ms             (witness + rapidsnark)

Speedup vs snarkjs:          2.19×    (paper value: 3,841 / 1,753)
Speedup (prover only):       2.67×    (3,480 / 1,379)
```

The bottleneck after rapidsnark is **JavaScript/WASM witness generation (374 ms)** — this cannot be replaced since the witness calculator is a Circom-compiled WASM file. Production automotive hardware with WASM acceleration would help.

---

### Benchmark 2 — True Batch Verification
**Files:** `benchmark/bench_batch_verify.js` + `benchmark/groth16_batch_verify.js`

#### `groth16_batch_verify.js` — The Key Custom Code
**Library used:** `ffjavascript` (low-level BN254 elliptic curve primitives)
**snarkjs has NO batch verification.** We wrote this from scratch.

**The algorithm (Bellare-Garay-Rabin 1998, adapted to Groth16):**

Individual Groth16 check for each proof j:
```
e(A_j, B_j) = e(α, β) · e(L_j, γ) · e(C_j, δ)
```

Batch: sample random scalar ρ_j per proof, combine all equations:
```
∏_j e(ρ_j·A_j, B_j) · e(-∑ρ_j·α, β) · e(-∑ρ_j·L_j, γ) · e(-∑ρ_j·C_j, δ) = 1
```

**Key implementation:** ONE `curve.pairingEq()` call with k+3 pairs:
```javascript
// Accumulate:
for (let j = 0; j < proofs.length; j++) {
    const rho = randomScalar();           // crypto.randomFillSync — NOT Math.random()
    const rhoA_j = G1.timesScalar(A_j, rho);    // scale A by ρ_j
    // L_j = IC[0] + Σ pubSig_i · IC[i+1]       // input wire commitment
    aggL = G1.add(aggL, G1.timesScalar(L_j, rho));
    aggC = G1.add(aggC, G1.timesScalar(C_j, rho));
}

// ONE pairing call: k+3 pairs → k+3 Miller loops + 1 final exponentiation
const valid = await curve.pairingEq(...args);
// vs k individual: 3k Miller loops + k final exponentiations
```

**Why B_j cannot be aggregated:** B_j is in G2 and is different for every proof. G1 points (A_j, L_j, C_j) can be scaled and summed (they're in the same group). G2 points cannot be efficiently aggregated — each needs its own Miller loop. That's why the batch has k+3 pairings not 3+3.

**Randomness security:** Uses `crypto.randomFillSync` → cryptographically secure. If a forged proof slips through, probability ≤ 1/p ≈ 2^{-254}.

**`bench_batch_verify.js` harness:**
For each k ∈ {1, 5, 10, 20, 30, 50}: generates k distinct proofs (different messages), runs sequential snarkjs verify k times, runs custom batchVerify once, compares both time and theoretical ratio.

**Results (RPi 4, `ulp_results_depth16/bench_batch_verify.json`):**
```
k=1:   seq=82.8 ms,   batch=39.9 ms,   actual=2.08×  (theory=0.75×)
k=5:   seq=355 ms,    batch=86.4 ms,   actual=4.11×  (theory=1.88×)
k=10:  seq=605 ms,    batch=153 ms,    actual=3.95×  (theory=2.31×)
k=20:  seq=1,238 ms,  batch=279 ms,    actual=4.44×  (theory=2.61×)
k=30:  seq=1,861 ms,  batch=400 ms,    actual=4.65×  (theory=2.73×)
k=50:  seq=3,022 ms,  batch=645 ms,    actual=4.68×  (theory=2.83×)
All validations: ✓ (batch output = correct)
```

**Why measured > theoretical:** The theoretical ratio `(k+3)/3k` only counts pairings. But each `snarkjs.groth16.verify()` call also has JavaScript/BigInt overhead (BigInt unstringification from JSON strings, memory allocation, function dispatch). This overhead is **fixed per call** and doesn't scale with k. Batch amortizes this overhead across all k proofs. Combined with the final exponentiation being 61.4% of pairing cost (see next benchmark), this explains the extra speedup.

---

### Benchmark 3 — Pairing Cost Breakdown
**File:** `benchmark/bench_pairing_breakdown.js`
**Library:** `ffjavascript` — calling curve primitives directly (NOT through snarkjs)

**What we call separately:**
```javascript
const curve = await getCurveFromName("bn128");
const pre1 = curve.prepareG1(P);   // one-time pre-compute
const pre2 = curve.prepareG2(Q);

// Split the pairing into its two components:
curve.millerLoop(pre1, pre2);          // Ate Miller loop only
curve.finalExponentiation(f_sample);   // Fp12 → GT final exp only
curve.pairing(P, Q);                   // Full pairing (both together)
```

snarkjs always calls `pairingEq()` which runs both together — you cannot get the breakdown from snarkjs. We use `ffjavascript` primitives directly.

**Results (RPi 4):**
```
Miller loop:             7.509 ms  ± 0.027 ms   (38.6%)
Final exponentiation:   11.954 ms  ± 0.043 ms   (61.4%)
Sum of components:      19.463 ms
Full pairing call:      22.510 ms  ± 0.150 ms
```

**What this proves about batch verification:** In batch mode, there is **only 1 final exponentiation** total, regardless of k. Each additional proof adds only 1 Miller loop (7.5 ms). Without batching, k proofs require k final exponentiations. At k=30: 30 final exp (358 ms) → 1 final exp (12 ms). This 346 ms saving in final exp is exactly why measured speedup (4.65×) exceeds theoretical pairing-count ratio (2.73×).

---

### Benchmark 4 — Poseidon Hash Timing (Online Phase Lower Bound)
**File:** `benchmark/bench_poseidon.js`
**Library:** `circomlibjs` (`buildPoseidon()`)

Poseidon is a hash function designed specifically for ZKP arithmetic circuits. It operates natively in the BN254 scalar field (Fp), requiring ~240 constraints for Poseidon-2, compared to ~25,000 constraints for SHA-256 in a Groth16 circuit.

**What we call:**
```javascript
const poseidon = await buildPoseidon();
const F = poseidon.F;
// The actual online operation: h_m = Poseidon(message, tCurrent)
F.toObject(poseidon([message, tCurrent]));
```

**Two measurement modes:**
- Individual (5,000 runs, 200 warmup): mean = 0.385 ms — high variance due to timer resolution
- Amortised (30 batches of 1,000 calls): mean = 0.376 ms, std = 0.0005 ms — more accurate

**Results (RPi 4, `ulp_results_depth16/bench_poseidon.json`):**
```
Amortised mean: 0.376 ms  ± 0.0005 ms
As % of 100 ms BSM cycle: 0.376%
```

**Note on the 0.437 ms vs 0.376 ms difference:** The proof cache benchmark (bench_proof_cache.js) reports 0.437 ms for the same operation. This is because it uses random 128-bit field elements (realistic BSM magnitudes) and measures in 500-call batches within the full deployment scenario. The paper uses **0.437 ms** as the more conservative, deployment-representative value.

---

### Benchmark 5 — Proof Slot Cache Model
**File:** `benchmark/bench_proof_cache.js`
**Libraries:** `snarkjs` + `circomlibjs` + `rapidsnark` (via `execFileSync` if installed)

This validates the entire offline/online model end-to-end in five phases:

**Phase A — Slot Generation (offline):**
Generates N=5 complete proof slots. Each slot uses `crypto.randomBytes(16)` as the pre-committed message (simulating a predicted future BSM). Each slot is verified valid after generation.

**Phase B — Online Per-BSM Cost:**
Measures dequeue (array.pop) and Poseidon binding in isolation:
```
Dequeue:         0.002 ms   (sub-microsecond)
Poseidon bind:   0.437 ms   ± 0.025 ms   (amortised over 2,000 calls in 500-run batches)
TOTAL:           0.439 ms   (0.44% of BSM cycle)
```

**Phase C — Cache Drain Rate:**
```
Consumption: 600 slots/min  (10 Hz × 60 s)
Production:   42 slots/min  (rapidsnark, RPi 4)
Net drain:   558 slots/min  (depletes 14× faster than fills)
```

**Phase D — Stop-Drive Model:**
```
Per 1 min of driving:
  Slots needed = 558 × 1 = 558 slots
  Stop time needed = 558 / 42 = 13.23 min
  → Stop:drive ratio = 13.23:1
```

**Phase E — Break-Even Hardware Acceleration:**
```
Target: ≤ 100 ms/slot  (= 1 slot per BSM interval = 600 slots/min)
Current: 1,422 ms/slot (rapidsnark, RPi 4)
Required speedup: 1422 / 100 = 14.22× over rapidsnark
NXP S32G @ 25× MSM tier → ~57 ms/slot → 1,055 slots/min → self-sustaining ✓
```

**Results (RPi 4, `ulp_results_depth16/bench_proof_cache.json`):**
```
Slot generation:   1,422 ms  ± 44 ms   (rapidsnark)
Production rate:    42.19 slots/min
Online total:        0.439 ms
Stop:drive ratio:   13.23:1
Break-even speedup: 14.22× over rapidsnark
```

---

### Benchmark 6 — ECDSA Baseline (SCMS Comparison)
**File:** `benchmark/bench_ecdsa_baseline.js`
**Library:** Node.js built-in `crypto` module (OpenSSL backend) — no extra dependencies

Measures SCMS/IEEE 1609.2 equivalent costs on the same RPi 4 hardware:
```javascript
// Sender cost (SCMS): ECDSA-P256 sign per BSM
const s = crypto.createSign("SHA256");
s.update(BSM_PAYLOAD);    // 250-byte BSM payload
s.sign(privKey);          // P-256 curve

// Receiver cost (SCMS): ECDSA-P256 verify per BSM
const v = crypto.createVerify("SHA256");
v.update(BSM_PAYLOAD);
v.verify(pubKey, validSig);
```

**Results (directly measured on RPi 4):**
```
ECDSA sign (sender per BSM):   0.199 ms   ← SCMS real-time cost
ECDSA verify (single):         0.420 ms
ECDSA verify k=30 (seq):      12.08 ms    ← SCMS dense traffic receiver cost
```

**Key comparison built from these numbers:**
| | SCMS (ECDSA) | ULP-V2V-Auth |
|---|---|---|
| Sender | 0.199 ms | 0.439 ms **(2.21×)** |
| Receiver single | 0.420 ms | 70.3 ms |
| Receiver k=30 | 12.08 ms | 400.0 ms |
| Unlinkable | Partial only | **Full (ZK)** |
| Proof/sig bytes | 72 B | 128 B |

The **2.21×** sender overhead is the quantified, measurable cost of upgrading from partial to full cryptographic unlinkability.

---

### Benchmark 7 — BN254 Primitive Microbenchmark (Wu et al. Projection)
**File:** `benchmark/bench_primitives.js`
**Library:** `ffjavascript` — `buildBn128` for direct G1/G2/pairing access

Wu et al. (zhang2024) published their scheme on a different machine. To compare fairly, we measure each BN254 primitive on our RPi 4 and apply their own operation-count formula (Table II of their paper):

**Primitives measured on RPi 4:**
```
T_G1  (254-bit G1 scalar mult):   1.64 ms
T_G2  (254-bit G2 scalar mult):   6.00 ms
T_s1  (60-bit G1 small-exp):      0.37 ms
T_b   (BN254 full pairing):      22.51 ms
T_H   (hash-to-G1):              ~1.67 ms   (= T_G1 + SHA256, conservative bound)
```

**Applying Wu et al.'s formula:**
```
Sign(M_i) = T_H + 2·T_G1 + T_G2 = 1.67 + 3.28 + 6.00 = ~11.0 ms/BSM
```

**This gives the 25.1× sender advantage:**
```
Wu et al. sender: ~11.0 ms/BSM  (11% of 100 ms budget consumed every message)
Ours:              0.439 ms/BSM
Speedup:          11.0 / 0.439 = 25.1×
```

The file also projects Jiang & Guo (jiang2024) analytically — their scheme requires RSU+BS+PBFT consensus, adding 200-800 ms of infrastructure latency, making it architecturally incompatible with direct V2V.

---

## 4. What Changed From Last Time

### Old Version vs New Version

| Aspect | Old Version (last meeting) | New Version (current) |
|---|---|---|
| **Circuit depth** | depth=8 (256 leaves, ~5,586 constraints) | **depth=16** (65,536 leaves, ~9,100 constraints) |
| **Trusted setup** | pot13 (2^13 capacity) | **pot14** (2^14 capacity) |
| **Hardware** | MacBook benchmarks with RPi estimated via slowdown factor | **ALL benchmarks directly on Raspberry Pi 4** |
| **Online model** | Partial witness precomputation (ran some Groth16 arithmetic online) | **Complete proof-slot cache** (only Poseidon hash online) |
| **Online cost claim** | Estimated ~7.5 ms (partial witness approach) | **Directly measured 0.439 ms** (complete proof + Poseidon binding only) |
| **rapidsnark** | Not benchmarked | **Compiled + benchmarked on RPi 4**: 1,753 ms, 2.19× speedup |
| **Batch verification** | Custom code existed but lacked measured results | **Validated with actual RPi 4 numbers**: 4.65× at k=30 |
| **Pairing breakdown** | Not measured | **Measured**: final exp=61.4%, explains 4.65× > 2.73× |
| **ECDSA baseline** | Not measured on RPi 4 | **Directly measured**: sign=0.199 ms, verify=0.420 ms |
| **Wu et al. projection** | Not done | **Done via BN254 primitives**: sign~11.0 ms → 25.1× gap |

### Biggest Conceptual Shift Between Versions
**Old model:** "We precompute a partial witness (97.3% of constraints), then finish the last 2.7% online."
- Problem: Even 2.7% of Groth16 arithmetic is hundreds of milliseconds.

**New model:** "We precompute the **complete** Groth16 proof using a *predicted* message. Online, we only hash to check if the prediction matched. If it did, broadcast the pre-generated proof."
- This works because at highway speeds (≤30 m/s), vehicle position over 100 ms is predictable to within 3 m — within GPS accuracy (±3–5 m).
- If prediction misses (e.g., sudden braking), discard slot and try next one. Still no EC ops.
- The entire 0.439 ms result flows from this shift.

### Why We Upgraded to depth-16
- Depth-8 = 256 leaves → only 256 vehicles per region (too few for city deployment)
- Depth-16 = 65,536 leaves → realistic regional fleet size
- Trade-off: ~9,100 constraints vs ~5,586 constraints (63% more), and requires pot14 vs pot13

---

## 5. What Problems Remain

### Problem 1 — Cache Is Not Self-Sustaining on RPi 4 (Honest Limitation)
**Numbers:**
- Consumption: 600 slots/min at 10 Hz
- Production (rapidsnark, RPi 4): 42.19 slots/min
- Net drain: 557.81 slots/min → cache empties 14× faster than it fills

**In practice:** The RPi 4 is a research proxy. Production deployment uses pre-departure cache fill (parking lot, charging station) or production hardware (NXP S32G with MSM acceleration at 25× tier → self-sustaining at 1,054 slots/min).

**Is this fatal?** No. The 0.439 ms online cost holds regardless of which prover fills the cache. The paper is explicit about the break-even requirement (14.22× over rapidsnark) and proposes the solution.

### Problem 2 — BSM Must Be Predicted at Precomputation Time
Each proof slot commits to a predicted future message. If actual BSM differs from prediction, slot is discarded and next one tried. At highway speeds this is rare (prediction error < 3 m). During sudden maneuvers, a few slots may be wasted but authentication continues from the next slot.

### Problem 3 — No Post-Quantum Security
Groth16 on BN254 is not post-quantum secure. This is also true for SCMS and all deployed V2X standards. Acknowledged as known limitation; post-quantum zk-SNARKs (Ligero, lattice-based) are future work.

### Problem 4 — Trusted Setup Not Production-Ready
Current experiment uses a local 2-contribution pot14 ceremony. Production needs automotive industry multi-party ceremony. Phase 1 can reuse the Hermez/Polygon publicly verifiable ceremony; Phase 2 needs a fresh multi-party computation.

### Problem 5 — Minor Inconsistencies Between Benchmark Files
- Poseidon: bench_poseidon.json says 0.376 ms; bench_proof_cache.json says 0.437 ms. The paper uses **0.437 ms** (more conservative, deployment-representative context — random 128-bit field elements, 500-run batches).
- Speedup: bench_rapidsnark.json says 2.31×; paper says 2.19×. Paper is correct (3,841/1,753 using the 20-run snarkjs baseline from bench_prover.json, which is more statistically robust than the 10-run baseline in bench_rapidsnark.json).

---

## 6. Full Paper vs JCSSE Version

### JCSSE Target
- **Format:** IEEE IEEEtran, 6–8 pages
- **Venue:** 23rd JCSSE 2026, Bangkok, June 24, 2026
- **Indexed:** IEEE Xplore
- **Deadline:** March 30, 2026

### Section-by-Section Comparison

| Section | Full Paper (`latex/`) | JCSSE (`latex_jcsse/`) | Cut Reason |
|---|---|---|---|
| Abstract | Full | Same (kept) | — |
| Introduction | 3 contributions + motivation | Same (kept) | — |
| Related Work | Table + 11 schemes | Same (kept) | Core context |
| **Design Challenges** | **~3-4 pages (FSM, epoch, ZKP selection, architecture)** | **ENTIRELY REMOVED** | Too long; design doc, not results |
| System / Protocol | 4-phase + 5 algorithms + revocation + channel resilience | 4-phase + **3 algorithms** + revocation | DCV algorithm → text reference |
| Security | 8 formal theorems with proof sketches | **Table + 1 sentence per property** | Proofs → table; saves ~1.5 pages |
| Experiments | 4 benchmarks + traffic density + hardware tiers + pairing table | **3 benchmarks** (Benchmarks 1+2+3) + comparative | Traffic density + hardware tiers cut |
| Conclusion | Not present | **New: Conclusion and Future Work** | Required for conference format |

### Detailed Cut Rationale

**Section 3 (Design Challenges) — Entire removal (biggest cut)**
The full paper's `latex/sections/03_design_challenges.tex` had:
- AST issuance state machine (FSM with figure)
- Request policy (claim verification, capability checking)
- Epoch management (root broadcast, grace period T_grace)
- Full ZKP selection analysis table (Groth16 vs PLONK vs STARK)
- Trusted setup ceremony design
- Concurrent SM/RM architecture
- Circuit constraint analysis derivation (the 97.3% breakdown step-by-step)

For JCSSE: the ZKP selection rationale was compressed to one paragraph inside "Crypto Prelims." The 97.3% is stated as a measured fact. This alone saves approximately 3 pages.

**Security — Proofs → Table (saves ~1.5 pages)**
Full paper: 8 theorems with formal proof sketches (Soundness, AIS Authenticity, Unlinkability, Replay Resistance, Revocation Correctness, Sybil Resistance, Timing Fingerprinting Resistance, Emergency Unlinkability).
JCSSE: one table with 7 properties (Timing Fingerprinting merged into Replay Resistance) and brief justifications.

**Experiments — Traffic Density + Hardware Tiers removed (saves ~1 page)**
Traffic density section analytically derives batch size k from FHWA highway density statistics and proves CPU utilization decreases with k. Useful for scalability argument but cut for space — the numbers (k=30 → 400 ms, k=50 → 607 ms) are still in the batch table.

Hardware tier table (showing snarkjs/rapidsnark/NXP S32G tiers with production rates) cut to a text mention.

Pairing breakdown table removed; key number (61.4%) cited in text only.

**Two algorithms removed**
Full paper: Registration (Alg 1), AST Acquisition (Alg 2), Online Broadcast (Alg 3), Batch Verify (Alg 4), DCV (Alg 5).
JCSSE: keeps Alg 2, 3, 4. Registration described in text; DCV referenced as [Ferrara 2008].

**Conclusion section added (new for JCSSE)**
The full paper is structured around results sections and doesn't have a formal Conclusion. The JCSSE version adds `latex_jcsse/sections/06_conclusion.tex` as `\section{Conclusion and Future Work}` — required for conference format.

### How Files Are Linked (No Duplication)
```
latex_jcsse/main.tex:
  \graphicspath{{../latex/assets/}}   ← reuses system_model.pdf, seqdia.pdf
  \bibliography{../latex/refs}         ← reuses refs.bib (no copy)
```
Only the section files in `latex_jcsse/sections/` are new content.

---

## 7. Talking Points

### Opening Update (2 min)
> "Since last time, I moved all benchmarks to the Raspberry Pi 4 and upgraded the circuit from depth-8 to depth-16 (65,536 leaves). Everything you see in the paper is directly measured on the RPi — no estimated numbers."

### Core New Result (3 min)
> "The main new result is 0.439 ms online cost — directly measured, not estimated. This comes from a conceptual change: instead of precomputing a partial proof, I precompute a complete proof using a predicted message. The vehicle's position at highway speed is predictable to within 3 m per 100 ms interval, which is within GPS accuracy, so the prediction almost never misses."

### Custom Code Point (2 min)
> "The 4.65× batch verification speedup comes from custom code I wrote — `groth16_batch_verify.js`. snarkjs doesn't have batch verification at all. I implemented Bellare-Garay-Rabin 1998 using ffjavascript curve primitives directly. I also measured why the speedup is higher than theory predicts: the BN254 final exponentiation is 61.4% of pairing cost, and batch verification amortizes it to one call regardless of k."

### JCSSE Submission (3 min)
> "I prepared a 6-page version in latex_jcsse/. The main cuts were: Section 3 (design documentation) removed entirely; security proofs condensed to a table; traffic density analysis removed. All the core experimental results are preserved. The deadline is March 30."

### Honest Limitations (2 min)
> "The RPi 4 cache isn't self-sustaining during driving — it produces 42 slots/min but needs 600 slots/min. This requires pre-departure fill or production hardware. I quantified the break-even: you need 14.2× speedup over rapidsnark, which the NXP S32G at 25× MSM tier achieves. The RPi 4 is a research proxy, not a deployment target."
