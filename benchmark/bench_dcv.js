/**
 * bench_dcv.js — Divide-and-Conquer Verification (DCV) Fallback Benchmark
 *
 * Validates Algorithm 4 (DCV Fallback) from Phase 4 of ULP-V2V-Auth.
 *
 * Paper claim (04_system.tex §Phase 4):
 *   "At k=30, w=1: DCV performs at most 2w⌈log₂ k⌉ = 2×5 = 10 sub-batch
 *    verifications versus 30 individual verifications under naive fallback.
 *    Each sub-batch of size k' ≤ 15 costs (k'+3) pairings ≪ 3k' individual;
 *    total DCV pairing cost is O(k + w log k) ≪ 3k."
 *
 * Each "sub-batch verification" here is one call to batchVerify() (from
 * groth16_batch_verify.js), which costs (k'+3) Miller loops + 1 final
 * exponentiation for a sub-batch of size k'.  The final exponentiation
 * dominates (~70% of pairing cost), so DCV does at most 10 final
 * exponentiations for w=1 vs 30 for naive individual verify.
 *
 * WHAT THIS MEASURES
 * ------------------
 *   [A] Baseline   — k=30 clean batch verify (1 call, should pass)
 *   [B] w=1 attack — 1 corrupted proof; DCV call count + timing
 *   [C] w=3 attack — 3 corrupted proofs; DCV call count + timing
 *   [D] Naive      — 30 individual snarkjs.groth16.verify calls
 *
 * Theoretical sub-batch call bounds:
 *   w=0 : 0  (batch verify passes outright, no DCV needed)
 *   w=1 : 2 × ⌈log₂ 30⌉          =  2×5  = 10
 *   w=3 : 2 × 3 × ⌈log₂(30/3)⌉  =  6×4  = 24  (bad proofs maximally spread)
 *
 * Proof cache: generated proofs are saved to results/dcv_proofs.json so
 * repeated runs skip the slow generation step.
 *
 * Run: node benchmark/bench_dcv.js
 * Prerequisites: npm run setup && npm run gen-input
 */

"use strict";
const snarkjs  = require("snarkjs");
const { batchVerify, buildBatchCurve } = require("./groth16_batch_verify");
const crypto   = require("crypto");
const fs       = require("fs");
const path     = require("path");
const os       = require("os");

// -------------------------------------------------------
// Config
// -------------------------------------------------------
const WASM = path.join("build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY = path.join("keys",  "ulp_v2v_auth_final.zkey");
const VK   = path.join("keys",  "verification_key.json");
const IN   = path.join("build", "input.json");

const K          = 30;    // batch size — matches paper's k=30 scenario
const N_RUNS     = 3;     // DCV/naive timing repetitions (for stable mean)
const PROOF_CACHE = path.join("results", "dcv_proofs.json");

// Bad proof positions for each scenario (chosen to test worst-case spread)
const W1_INDEX  = 14;                  // w=1: index near middle
const W3_INDICES = [0, 10, 20];        // w=3: maximally spread

// -------------------------------------------------------
// Helpers
// -------------------------------------------------------
function detectHardware() {
    if (process.platform === "linux" && fs.existsSync("/proc/cpuinfo")) {
        const info = fs.readFileSync("/proc/cpuinfo", "utf8");
        const m = info.match(/^Model\s*:\s*(.+)$/m);
        if (m) return m[1].trim();
        const h = info.match(/^Hardware\s*:\s*(.+)$/m);
        if (h) return `Linux/${h[1].trim()}`;
    }
    const cpu = os.cpus()[0]?.model ?? "Unknown";
    return `${process.platform === "darwin" ? "macOS" : os.platform()} — ${cpu}`;
}

const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
const ci95 = arr => {
    const m = mean(arr);
    const s = Math.sqrt(arr.reduce((acc, x) => acc + (x - m) ** 2, 0) / arr.length);
    return 1.96 * s / Math.sqrt(arr.length);
};

/** Corrupt a proof by perturbing pi_a[0] — ensures verify() returns false. */
function corruptProof(proof) {
    const corrupted = JSON.parse(JSON.stringify(proof)); // deep copy
    // Increment pi_a x-coordinate by 1 — point is no longer on BN254 G1
    corrupted.pi_a[0] = (BigInt(corrupted.pi_a[0]) + BigInt(1)).toString();
    return corrupted;
}

/**
 * Theoretical DCV sub-batch call bound:
 *   2 * w * ceil(log2(k / w))
 * for w > 0; 0 for w = 0 (batch verify passes immediately).
 */
function theoreticalDcvCalls(k, w) {
    if (w === 0) return 0;
    return 2 * w * Math.ceil(Math.log2(k / w));
}

// -------------------------------------------------------
// DCV Algorithm (Algorithm 4, Phase 4)
// -------------------------------------------------------
/**
 * dcv(proofs, pubSignals, vk, curve, counter)
 *
 * Recursively identifies and isolates corrupted proofs.
 * Increments counter.calls for each sub-batch verification made.
 * Returns { valid: boolean, badIndices: number[] }.
 *
 * Outer caller should first run batchVerify on the full set; only call
 * this function when the initial batch verify FAILS.
 */
async function dcv(proofs, pubSignals, vk, curve, counter) {
    const k = proofs.length;

    if (k === 1) {
        // Base case: individual verify
        counter.calls++;
        const res = await batchVerify(proofs, pubSignals, vk, curve);
        return { valid: res.valid, badIndices: res.valid ? [] : [0] };
    }

    const mid = Math.floor(k / 2);
    const leftProofs  = proofs.slice(0, mid);
    const leftPubs    = pubSignals.slice(0, mid);
    const rightProofs = proofs.slice(mid);
    const rightPubs   = pubSignals.slice(mid);

    // Verify both halves — both must be checked to know which contains bad proofs
    counter.calls++;
    const leftRes = await batchVerify(leftProofs, leftPubs, vk, curve);
    counter.calls++;
    const rightRes = await batchVerify(rightProofs, rightPubs, vk, curve);

    let badIndices = [];

    if (!leftRes.valid) {
        const rec = await dcv(leftProofs, leftPubs, vk, curve, counter);
        badIndices.push(...rec.badIndices);
    }
    if (!rightRes.valid) {
        const rec = await dcv(rightProofs, rightPubs, vk, curve, counter);
        badIndices.push(...rec.badIndices.map(i => i + mid));
    }

    return { valid: badIndices.length === 0, badIndices };
}

// -------------------------------------------------------
// Proof generation (with cache)
// -------------------------------------------------------
async function loadOrGenerateProofs(k, baseInput) {
    fs.mkdirSync("results", { recursive: true });

    if (fs.existsSync(PROOF_CACHE)) {
        try {
            const cached = JSON.parse(fs.readFileSync(PROOF_CACHE));
            if (cached.k >= k && Array.isArray(cached.proofs) && cached.proofs.length >= k) {
                console.log(`  Loaded ${k} proofs from cache (${PROOF_CACHE}).`);
                return cached.proofs.slice(0, k);
            }
        } catch { /* fall through to regeneration */ }
    }

    console.log(`  Generating ${k} proofs (first run — will be cached)...`);
    const entries = [];
    for (let i = 0; i < k; i++) {
        const pkOt = (BigInt(baseInput.pkOt) + BigInt(i + 1)).toString();
        const inp  = { ...baseInput, pkOt };
        process.stdout.write(`  Proof ${i+1}/${k}  \r`);
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(inp, WASM, ZKEY);
        entries.push({ proof, publicSignals });
    }
    console.log(`  Generated ${k} proofs.                   `);

    fs.writeFileSync(PROOF_CACHE, JSON.stringify({ k, proofs: entries }, null, 2));
    console.log(`  Proof cache saved to ${PROOF_CACHE}`);
    return entries;
}

// -------------------------------------------------------
// Main
// -------------------------------------------------------
async function main() {
    const hw = detectHardware();
    console.log("=".repeat(68));
    console.log("  ULP-V2V-Auth — DCV Fallback Benchmark (Algorithm 4)");
    console.log(`  Hardware : ${hw}`);
    console.log(`  k = ${K} proofs,  N_RUNS = ${N_RUNS} timing repetitions`);
    console.log("=".repeat(68));

    for (const f of [WASM, ZKEY, VK, IN]) {
        if (!fs.existsSync(f)) {
            console.error(`Missing: ${f} — run npm run setup && npm run gen-input`);
            process.exit(1);
        }
    }

    const baseInput  = JSON.parse(fs.readFileSync(IN));
    const vk         = JSON.parse(fs.readFileSync(VK));
    const batchCurve = await buildBatchCurve();

    // Load or generate k=30 valid proofs
    const entries    = await loadOrGenerateProofs(K, baseInput);
    const cleanProofs  = entries.map(e => e.proof);
    const cleanPubs    = entries.map(e => e.publicSignals);

    // Verify all proofs are valid (sanity check)
    console.log(`\n  Sanity check: verifying ${K} generated proofs individually...`);
    let allValid = true;
    for (let i = 0; i < K; i++) {
        const ok = await snarkjs.groth16.verify(vk, cleanPubs[i], cleanProofs[i]);
        if (!ok) { console.error(`  ✗ Proof ${i} is INVALID (re-run gen-input)`); allValid = false; }
    }
    if (allValid) console.log(`  ✓ All ${K} proofs valid.`);
    else { process.exit(1); }

    const allResults = {};

    // -------------------------------------------------------
    // [A] Baseline: k=30 clean batch verify
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[A] Baseline: batch verify of k=${K} clean proofs`);
    console.log(`    Expected: 1 batch verify call, PASS`);
    console.log(`${"─".repeat(68)}`);

    const baselineTimes = [];
    let baselineValid = false;
    for (let r = 0; r < N_RUNS; r++) {
        const t0 = performance.now();
        const res = await batchVerify(cleanProofs, cleanPubs, vk, batchCurve);
        baselineTimes.push(performance.now() - t0);
        baselineValid = res.valid;
    }
    const baselineMean = mean(baselineTimes);
    const baselineCI   = ci95(baselineTimes);

    console.log(`  Result  : ${baselineValid ? "✓ PASS" : "✗ FAIL (check proofs)"}`);
    console.log(`  Time    : ${baselineMean.toFixed(1)} ms ± ${baselineCI.toFixed(1)} ms (95% CI)`);
    console.log(`  Pairings: ${K + 3}  (= k+3 = ${K}+3)`);
    allResults.baseline = { valid: baselineValid, mean_ms: parseFloat(baselineMean.toFixed(2)), ci95_ms: parseFloat(baselineCI.toFixed(2)) };

    // -------------------------------------------------------
    // [B] w=1: single corrupted proof
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[B] w=1 adversarial injection: corrupt proof at index ${W1_INDEX}`);
    console.log(`    Expected calls: 2 × ⌈log₂ ${K}⌉ = ${theoreticalDcvCalls(K, 1)}`);
    console.log(`${"─".repeat(68)}`);

    const w1Proofs = [...cleanProofs];
    w1Proofs[W1_INDEX] = corruptProof(cleanProofs[W1_INDEX]);

    // Confirm initial batch fails
    const w1InitialBatch = await batchVerify(w1Proofs, cleanPubs, vk, batchCurve);
    console.log(`  Initial batch verify (k=30): ${w1InitialBatch.valid ? "✓ PASS (corruption undetected!)" : "✗ FAIL (expected — triggers DCV)"}`);

    const w1DcvTimes = [];
    let w1Counter = { calls: 0 };
    let w1Result;
    for (let r = 0; r < N_RUNS; r++) {
        w1Counter = { calls: 0 };
        const t0 = performance.now();
        w1Result = await dcv(w1Proofs, cleanPubs, vk, batchCurve, w1Counter);
        w1DcvTimes.push(performance.now() - t0);
    }
    const w1Mean = mean(w1DcvTimes);
    const w1CI   = ci95(w1DcvTimes);
    const w1Theory = theoreticalDcvCalls(K, 1);

    console.log(`  DCV call count  : ${w1Counter.calls}  (theoretical ≤ ${w1Theory})  ${w1Counter.calls <= w1Theory ? "✓" : "✗ EXCEEDS BOUND"}`);
    console.log(`  Bad proofs found: indices [${w1Result.badIndices.join(", ")}]  (expected [${W1_INDEX}])  ${w1Result.badIndices.includes(W1_INDEX) ? "✓" : "✗ WRONG INDEX"}`);
    console.log(`  DCV time        : ${w1Mean.toFixed(1)} ms ± ${w1CI.toFixed(1)} ms (95% CI)`);
    allResults.w1 = {
        corruptedIndex: W1_INDEX,
        dcvCalls: w1Counter.calls,
        theoreticalBound: w1Theory,
        callBoundMet: w1Counter.calls <= w1Theory,
        badIndicesFound: w1Result.badIndices,
        mean_ms: parseFloat(w1Mean.toFixed(2)),
        ci95_ms: parseFloat(w1CI.toFixed(2)),
    };

    // -------------------------------------------------------
    // [C] w=3: three corrupted proofs (maximally spread)
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[C] w=3 adversarial injection: corrupt proofs at indices [${W3_INDICES.join(", ")}]`);
    console.log(`    Expected calls: 2×3×⌈log₂(${K}/3)⌉ = ${theoreticalDcvCalls(K, 3)}`);
    console.log(`${"─".repeat(68)}`);

    const w3Proofs = [...cleanProofs];
    for (const idx of W3_INDICES) w3Proofs[idx] = corruptProof(cleanProofs[idx]);

    const w3InitialBatch = await batchVerify(w3Proofs, cleanPubs, vk, batchCurve);
    console.log(`  Initial batch verify (k=30): ${w3InitialBatch.valid ? "✓ PASS (unexpected!)" : "✗ FAIL (expected — triggers DCV)"}`);

    const w3DcvTimes = [];
    let w3Counter = { calls: 0 };
    let w3Result;
    for (let r = 0; r < N_RUNS; r++) {
        w3Counter = { calls: 0 };
        const t0 = performance.now();
        w3Result = await dcv(w3Proofs, cleanPubs, vk, batchCurve, w3Counter);
        w3DcvTimes.push(performance.now() - t0);
    }
    const w3Mean = mean(w3DcvTimes);
    const w3CI   = ci95(w3DcvTimes);
    const w3Theory = theoreticalDcvCalls(K, 3);
    const w3Expected = W3_INDICES.join(", ");
    const w3Found    = [...w3Result.badIndices].sort((a,b)=>a-b).join(", ");

    console.log(`  DCV call count  : ${w3Counter.calls}  (theoretical ≤ ${w3Theory})  ${w3Counter.calls <= w3Theory ? "✓" : "✗ EXCEEDS BOUND"}`);
    console.log(`  Bad proofs found: indices [${w3Found}]  (expected [${w3Expected}])  ${w3Found === w3Expected ? "✓" : "✗ MISMATCH"}`);
    console.log(`  DCV time        : ${w3Mean.toFixed(1)} ms ± ${w3CI.toFixed(1)} ms (95% CI)`);
    allResults.w3 = {
        corruptedIndices: W3_INDICES,
        dcvCalls: w3Counter.calls,
        theoreticalBound: w3Theory,
        callBoundMet: w3Counter.calls <= w3Theory,
        badIndicesFound: w3Result.badIndices,
        mean_ms: parseFloat(w3Mean.toFixed(2)),
        ci95_ms: parseFloat(w3CI.toFixed(2)),
    };

    // -------------------------------------------------------
    // [D] Naive fallback: k=30 individual verify calls
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[D] Naive fallback: ${K} individual snarkjs.groth16.verify calls`);
    console.log(`    Comparison baseline for DCV speedup calculation`);
    console.log(`${"─".repeat(68)}`);

    const naiveTimes = [];
    for (let r = 0; r < N_RUNS; r++) {
        const t0 = performance.now();
        for (let i = 0; i < K; i++) {
            await snarkjs.groth16.verify(vk, cleanPubs[i], cleanProofs[i]);
        }
        naiveTimes.push(performance.now() - t0);
    }
    const naiveMean = mean(naiveTimes);
    const naiveCI   = ci95(naiveTimes);

    console.log(`  Total time (${K} verifies) : ${naiveMean.toFixed(1)} ms ± ${naiveCI.toFixed(1)} ms (95% CI)`);
    console.log(`  Per-proof              : ${(naiveMean / K).toFixed(1)} ms`);
    allResults.naive = {
        calls: K,
        mean_ms: parseFloat(naiveMean.toFixed(2)),
        ci95_ms: parseFloat(naiveCI.toFixed(2)),
        perProof_ms: parseFloat((naiveMean / K).toFixed(3)),
    };

    // -------------------------------------------------------
    // Summary
    // -------------------------------------------------------
    console.log("\n" + "=".repeat(68));
    console.log("  DCV Fallback Summary — ULP-V2V-Auth Phase 4");
    console.log("=".repeat(68));

    const w1Speedup = naiveMean / w1Mean;
    const w3Speedup = naiveMean / w3Mean;

    console.log(`\n  ${"Scenario".padEnd(20)} ${"DCV calls".padStart(10)} ${"Theory ≤".padStart(10)} ${"Time (ms)".padStart(12)} ${"vs Naive".padStart(10)}`);
    console.log("  " + "─".repeat(68));
    console.log(`  ${"Baseline (w=0)".padEnd(20)} ${String(0).padStart(10)} ${String(0).padStart(10)} ${baselineMean.toFixed(1).padStart(12)} ${(naiveMean/baselineMean).toFixed(2).padStart(9)}×`);
    console.log(`  ${"w=1 (idx 14)".padEnd(20)} ${String(w1Counter.calls).padStart(10)} ${String(w1Theory).padStart(10)} ${w1Mean.toFixed(1).padStart(12)} ${w1Speedup.toFixed(2).padStart(9)}×`);
    console.log(`  ${"w=3 (idx 0,10,20)".padEnd(20)} ${String(w3Counter.calls).padStart(10)} ${String(w3Theory).padStart(10)} ${w3Mean.toFixed(1).padStart(12)} ${w3Speedup.toFixed(2).padStart(9)}×`);
    console.log(`  ${"Naive (k=30 indiv)".padEnd(20)} ${String(K).padStart(10)} ${"—".padStart(10)} ${naiveMean.toFixed(1).padStart(12)} ${"1.00×".padStart(10)}`);

    console.log(`\n  Paper claim check:`);
    console.log(`    w=1 calls (${w1Counter.calls}) ≤ theoretical bound (${w1Theory})  →  ${w1Counter.calls <= w1Theory ? "✓ PASS" : "✗ FAIL"}`);
    console.log(`    w=3 calls (${w3Counter.calls}) ≤ theoretical bound (${w3Theory})  →  ${w3Counter.calls <= w3Theory ? "✓ PASS" : "✗ FAIL"}`);
    console.log(`    DCV (w=1) speedup vs naive: ${w1Speedup.toFixed(2)}×`);

    // -------------------------------------------------------
    // Save results
    // -------------------------------------------------------
    const output = {
        hardware     : hw,
        circuit      : "ULP_V2V_Auth(depth=8, constraints=5069)",
        k            : K,
        nRuns        : N_RUNS,
        timestamp    : new Date().toISOString(),
        ...allResults,
        speedup      : {
            dcvW1VsNaive : parseFloat(w1Speedup.toFixed(3)),
            dcvW3VsNaive : parseFloat(w3Speedup.toFixed(3)),
            baselineVsNaive: parseFloat((naiveMean/baselineMean).toFixed(3)),
        },
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_dcv.json");
    fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
    console.log(`\nResults saved to ${outPath}`);
    console.log("Update paper TODO flags in 04_system.tex with DCV call counts and speedup.");

    await batchCurve.terminate();
}

main().catch(err => { console.error(err); process.exit(1); });
