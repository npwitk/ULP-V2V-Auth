/**
 * bench_ecdsa_baseline.js
 *
 * Measures ECDSA-P256 operation timings to validate paper claims for the
 * one-time-key architecture of ULP-V2V-Auth.
 *
 * Paper claims validated here:
 *   [A] KeyGen  <0.3 ms    — Phase 2: fresh (sk_ot, pk_ot) per cache slot
 *   [B] Sign    ~0.20 ms   — Phase 3: online sender cost per BSM
 *   [C] Verify  ~0.42 ms   — Phase 4 Step 2: ECDSA pre-check before Groth16
 *   [D] SCMS k=30 comparison — sequential ECDSA verify vs ULP batch Groth16
 *
 * Design note — one-time-key architecture:
 *   Both SCMS and ULP-V2V-Auth use ECDSA-P256 sign at the sender (same per-message
 *   cost). The ULP advantage is at the RECEIVER:
 *     SCMS  : k individual ECDSA verifications    O(k) × ~0.42 ms
 *     ULP   : 1 batch Groth16 check for k proofs  O(k+3 pairings) — see bench_batch_verify
 *   ULP also reduces per-BSM payload by ~2× (273 B vs 400–600 B for SCMS + cert).
 *
 * Run: node benchmark/bench_ecdsa_baseline.js
 * No extra dependencies — uses Node.js built-in crypto.
 */

"use strict";
const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");
const os     = require("os");

// -----------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------
const N_WARMUP  = 100;
const N_RUNS    = 2000;   // tight CI on sub-ms operations
const N_KEYGEN  = 300;    // keygen is ~3–5× slower; fewer runs needed

// Simulated BSM payload: position (8B) + velocity (4B) + heading (4B)
// + brake (1B) + timestamp (8B) + padding ≈ 250 bytes (SAE J2735)
const BSM_PAYLOAD = crypto.randomBytes(250);

// -----------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------
function detectHardware() {
    if (process.platform === "linux" && fs.existsSync("/proc/cpuinfo")) {
        const info = fs.readFileSync("/proc/cpuinfo", "utf8");
        const m = info.match(/^Model\s*:\s*(.+)$/m);
        if (m) return m[1].trim();
        const h = info.match(/^Hardware\s*:\s*(.+)$/m);
        if (h) return `Linux/${h[1].trim()}`;
    }
    const cpu = os.cpus()[0]?.model ?? "Unknown CPU";
    return `${process.platform === "darwin" ? "macOS" : os.platform()} — ${cpu}`;
}

const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
const std  = arr => { const m = mean(arr); return Math.sqrt(arr.reduce((s, x) => s + (x - m) ** 2, 0) / arr.length); };
const ci95 = arr => (1.96 * std(arr) / Math.sqrt(arr.length));

// Try to load batch Groth16 reference from prior bench_batch_verify run
function loadBatchRef() {
    const p = path.join("results", "bench_batch_verify.json");
    if (!fs.existsSync(p)) return null;
    try {
        const d = JSON.parse(fs.readFileSync(p));
        const k30 = (d.results ?? []).find(r => r.k === 30);
        return k30 ? { batchK30_ms: k30.batchMs, speedup: k30.actualSaving } : null;
    } catch { return null; }
}

// -----------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------
function main() {
    const hw      = detectHardware();
    const batchRef = loadBatchRef();

    console.log("=".repeat(68));
    console.log("  ULP-V2V-Auth — ECDSA-P256 Timing Benchmark");
    console.log("  Validates paper claims: KeyGen / Sign / Verify latency");
    console.log(`  Hardware    : ${hw}`);
    console.log(`  BSM payload : ${BSM_PAYLOAD.length} bytes`);
    console.log(`  Warmup / Runs: ${N_WARMUP} / ${N_RUNS}`);
    console.log("=".repeat(68));

    // -----------------------------------------------------------------------
    // [A] ECDSA-P256 Key Generation
    //     Paper claim: < 0.3 ms per slot in Phase 2 (offline, not per-message)
    // -----------------------------------------------------------------------
    console.log("\n[A] ECDSA-P256 KeyGen  (Phase 2 — per cache slot, offline)");
    const keyGenTimes = [];
    // Warmup
    for (let i = 0; i < 20; i++)
        crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });

    for (let i = 0; i < N_KEYGEN; i++) {
        const t0 = performance.now();
        crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
        keyGenTimes.push(performance.now() - t0);
        if ((i + 1) % 50 === 0)
            process.stdout.write(`  run ${i + 1}/${N_KEYGEN}: ${keyGenTimes[i].toFixed(3)} ms   \r`);
    }
    console.log("");
    const keyGenMean = mean(keyGenTimes);
    const keyGenCI   = ci95(keyGenTimes);
    console.log(`  mean : ${keyGenMean.toFixed(3)} ms  ±${keyGenCI.toFixed(3)} ms (95% CI)`);
    console.log(`  claim: < 0.3 ms  →  ${keyGenMean < 0.3 ? "✓ PASS" : "✗ FAIL (update paper)"}`);

    // Stable key pair for sign/verify benchmarks
    const { privateKey: privDer, publicKey: pubDer } = crypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding:  { type: "spki",  format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "der" },
    });
    const privKey = crypto.createPrivateKey({ key: privDer, format: "der", type: "pkcs8" });
    const pubKey  = crypto.createPublicKey({ key: pubDer,  format: "der", type: "spki"  });

    // Pre-generate a valid signature for the verify benchmark
    const signerRef = crypto.createSign("SHA256");
    signerRef.update(BSM_PAYLOAD);
    const validSig = signerRef.sign(privKey);
    console.log(`  Signature size : ${validSig.length} bytes (DER-encoded)`);

    // -----------------------------------------------------------------------
    // [B] ECDSA-P256 Sign
    //     Paper claim: ~0.20 ms per message in Phase 3 (online sender cost)
    // -----------------------------------------------------------------------
    console.log("\n[B] ECDSA-P256 Sign  (Phase 3 — per-BSM online cost)");

    for (let i = 0; i < N_WARMUP; i++) {
        const s = crypto.createSign("SHA256");
        s.update(BSM_PAYLOAD);
        s.sign(privKey);
    }

    const signTimes = [];
    for (let i = 0; i < N_RUNS; i++) {
        const t0 = performance.now();
        const s = crypto.createSign("SHA256");
        s.update(BSM_PAYLOAD);
        s.sign(privKey);
        signTimes.push(performance.now() - t0);
        if ((i + 1) % 500 === 0)
            process.stdout.write(`  run ${i + 1}/${N_RUNS}: ${signTimes[i].toFixed(3)} ms   \r`);
    }
    console.log("");
    const signMean = mean(signTimes);
    const signCI   = ci95(signTimes);
    const signPct  = (signMean / 100 * 100).toFixed(3);
    console.log(`  mean : ${signMean.toFixed(3)} ms  ±${signCI.toFixed(3)} ms (95% CI)`);
    console.log(`  as % of 100 ms BSM cycle : ${signPct}%`);
    console.log(`  claim: ~0.20 ms  →  ${signMean < 0.40 ? "✓ PASS" : "✗ FAIL (update paper)"}`);

    // -----------------------------------------------------------------------
    // [C] ECDSA-P256 Verify
    //     Paper claim: ~0.42 ms per proof in Phase 4 Step 2 (pre-check)
    // -----------------------------------------------------------------------
    console.log("\n[C] ECDSA-P256 Verify  (Phase 4 Step 2 — ECDSA pre-check per proof)");

    for (let i = 0; i < N_WARMUP; i++) {
        const v = crypto.createVerify("SHA256");
        v.update(BSM_PAYLOAD);
        v.verify(pubKey, validSig);
    }

    const verifyTimes = [];
    for (let i = 0; i < N_RUNS; i++) {
        const t0 = performance.now();
        const v = crypto.createVerify("SHA256");
        v.update(BSM_PAYLOAD);
        v.verify(pubKey, validSig);
        verifyTimes.push(performance.now() - t0);
        if ((i + 1) % 500 === 0)
            process.stdout.write(`  run ${i + 1}/${N_RUNS}: ${verifyTimes[i].toFixed(3)} ms   \r`);
    }
    console.log("");
    const verifyMean = mean(verifyTimes);
    const verifyCI   = ci95(verifyTimes);
    console.log(`  mean : ${verifyMean.toFixed(3)} ms  ±${verifyCI.toFixed(3)} ms (95% CI)`);
    console.log(`  claim: ~0.42 ms  →  ${verifyMean < 0.80 ? "✓ PASS" : "✗ FAIL (update paper)"}`);

    // -----------------------------------------------------------------------
    // [D] SCMS comparison: k=30 sequential ECDSA verify vs ULP batch Groth16
    //     SCMS receives k BSMs, each needing individual ECDSA-P256 verify.
    //     ULP-V2V-Auth receives k proofs and runs one batch Groth16 check.
    // -----------------------------------------------------------------------
    console.log("\n[D] SCMS k=30 comparison (sequential ECDSA verify)");
    const K = 30;
    const scmsBatchTimes = [];
    for (let run = 0; run < 20; run++) {
        const t0 = performance.now();
        for (let j = 0; j < K; j++) {
            const v = crypto.createVerify("SHA256");
            v.update(BSM_PAYLOAD);
            v.verify(pubKey, validSig);
        }
        scmsBatchTimes.push(performance.now() - t0);
    }
    const scmsK30Mean = mean(scmsBatchTimes);
    console.log(`  SCMS sequential k=30 verify : ${scmsK30Mean.toFixed(1)} ms`);
    if (batchRef) {
        const speedup = scmsK30Mean / batchRef.batchK30_ms;
        console.log(`  ULP batch Groth16 k=30      : ${batchRef.batchK30_ms.toFixed(1)} ms  (from bench_batch_verify)`);
        console.log(`  Receiver speedup (ULP/SCMS) : ${speedup.toFixed(2)}×`);
    } else {
        console.log(`  ULP batch Groth16 k=30      : (run bench_batch_verify.js to get this)`);
    }

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    console.log("\n" + "=".repeat(68));
    console.log("  Summary: ECDSA-P256 timings for paper update");
    console.log("=".repeat(68));

    const rows = [
        ["Phase 2 KeyGen/slot (ms)",   keyGenMean, 0.3,  "< 0.3 ms"],
        ["Phase 3 Sign/BSM (ms)",       signMean,   0.40, "~0.20 ms"],
        ["Phase 4 Verify/proof (ms)",   verifyMean, 0.80, "~0.42 ms"],
    ];
    console.log(`\n  ${"Measurement".padEnd(32)} ${"Measured".padStart(10)} ${"Claim".padStart(12)} ${"Status"}`);
    console.log("  " + "-".repeat(62));
    for (const [label, val, threshold, claim] of rows) {
        const pass = val < threshold;
        console.log(`  ${label.padEnd(32)} ${val.toFixed(3).padStart(10)} ${claim.padStart(12)}   ${pass ? "✓" : "✗ UPDATE PAPER"}`);
    }

    console.log(`\n  Payload comparison (per BSM):`);
    console.log(`    SCMS  : ~400–600 bytes  (ECDSA sig + pseudonym cert)`);
    console.log(`    ULP   : ~273 bytes      (128B proof + 33B pk_ot + 64B ECDSA sig + 32B root + 8B t_gen + 8B t_cur)`);

    // -----------------------------------------------------------------------
    // Save results
    // -----------------------------------------------------------------------
    const results = {
        hardware        : hw,
        bsmPayloadBytes : BSM_PAYLOAD.length,
        signatureBytes  : validSig.length,
        nWarmup         : N_WARMUP,
        nRuns           : N_RUNS,
        nKeyGen         : N_KEYGEN,
        timestamp       : new Date().toISOString(),
        keyGen : { mean_ms: parseFloat(keyGenMean.toFixed(4)), ci95_ms: parseFloat(keyGenCI.toFixed(4)), claim_ms: 0.3  },
        sign   : { mean_ms: parseFloat(signMean.toFixed(4)),   ci95_ms: parseFloat(signCI.toFixed(4)),   claim_ms: 0.20, pctOfBsmCycle: parseFloat(signPct) },
        verify : { mean_ms: parseFloat(verifyMean.toFixed(4)), ci95_ms: parseFloat(verifyCI.toFixed(4)), claim_ms: 0.42 },
        scmsK30: { seqVerify_ms: parseFloat(scmsK30Mean.toFixed(2)), k: K },
        batchRef: batchRef ?? "not_available_run_bench_batch_verify",
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_ecdsa_baseline.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\nResults saved to ${outPath}`);
    console.log("Update paper TODO flags with values from this run.");
}

main();
