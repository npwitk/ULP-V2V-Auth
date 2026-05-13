/**
 * bench_scms_batch.js — SCMS Receiver-Side Batch Verification Baseline
 *
 * Measures SCMS (IEEE 1609.2) receiver-side cost: k sequential ECDSA-P256
 * verifications for k=18 (free flow), k=30 (moderate), k=50 (dense traffic).
 *
 * This provides the SCMS baseline for Table IV in the SNAP paper,
 * enabling a direct comparison against SNAP's batch Groth16 verification.
 *
 * METHOD:
 *   SCMS receiver verifies each incoming BSM by checking the sender's
 *   ECDSA-P256 signature individually. There is no batch verification
 *   in IEEE 1609.2 WAVE security — each message requires one ECDSA verify.
 *   We measure wall-clock time for k sequential ECDSA-P256 verifications.
 *
 * Run: node benchmark/bench_scms_batch.js
 * No extra dependencies — uses Node.js built-in crypto.
 *
 * Output: results/bench_scms_batch.json
 */

"use strict";

const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");
const os     = require("os");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const N_WARMUP   = 20;
const N_RUNS     = 20;     // matches SNAP batch verify methodology in paper
const BATCH_SIZES = [18, 30, 50];

const BSM_PAYLOAD = crypto.randomBytes(250);

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
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
const std  = arr => {
    const m = mean(arr);
    return Math.sqrt(arr.reduce((s, x) => s + (x - m) ** 2, 0) / arr.length);
};
const ci95 = arr => 1.96 * std(arr) / Math.sqrt(arr.length);

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
    const hw = detectHardware();

    console.log("=".repeat(68));
    console.log("  SNAP Paper — SCMS Receiver-Side Batch Verification Baseline");
    console.log("  k sequential ECDSA-P256 verifications (IEEE 1609.2 WAVE)");
    console.log(`  Hardware       : ${hw}`);
    console.log(`  Warmup / Runs  : ${N_WARMUP} / ${N_RUNS}`);
    console.log(`  Batch sizes    : ${BATCH_SIZES.join(", ")}`);
    console.log("=".repeat(68));

    // Generate one key pair and one valid signature (reused across verifications
    // to isolate pure crypto cost, same as SNAP batch verify methodology)
    const { privateKey: privDer, publicKey: pubDer } = crypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
        privateKeyEncoding: { type: "pkcs8", format: "der" },
        publicKeyEncoding:  { type: "spki",  format: "der" },
    });
    const privKey = crypto.createPrivateKey({ key: privDer, format: "der", type: "pkcs8" });
    const pubKey  = crypto.createPublicKey({ key: pubDer, format: "der", type: "spki" });

    const signerRef = crypto.createSign("SHA256");
    signerRef.update(BSM_PAYLOAD);
    const validSig = signerRef.sign(privKey);
    console.log(`\n  Signature size : ${validSig.length} bytes (DER-encoded ECDSA-P256)`);

    // Warmup
    console.log(`\n  Warming up (${N_WARMUP} single-verify iterations)...`);
    for (let i = 0; i < N_WARMUP; i++) {
        const v = crypto.createVerify("SHA256");
        v.update(BSM_PAYLOAD);
        v.verify(pubKey, validSig);
    }
    console.log("  Done.\n");

    // -----------------------------------------------------------------------
    // Benchmark each batch size
    // -----------------------------------------------------------------------
    const results = [];

    console.log(`  ${"k".padStart(4)}  ${"Mean (ms)".padStart(10)}  ${"Std (ms)".padStart(10)}  ${"95% CI (ms)".padStart(12)}  ${"Per-verify (ms)".padStart(16)}`);
    console.log("  " + "─".repeat(58));

    for (const k of BATCH_SIZES) {
        const times = [];

        for (let run = 0; run < N_RUNS; run++) {
            const t0 = performance.now();
            for (let j = 0; j < k; j++) {
                const v = crypto.createVerify("SHA256");
                v.update(BSM_PAYLOAD);
                v.verify(pubKey, validSig);
            }
            times.push(performance.now() - t0);
        }

        const m   = mean(times);
        const s   = std(times);
        const ci  = ci95(times);
        const perV = m / k;

        console.log(`  ${String(k).padStart(4)}  ${m.toFixed(2).padStart(10)}  ${s.toFixed(2).padStart(10)}  ${ci.toFixed(2).padStart(12)}  ${perV.toFixed(3).padStart(16)}`);

        results.push({
            k,
            mean_ms   : parseFloat(m.toFixed(3)),
            std_ms    : parseFloat(s.toFixed(3)),
            ci95_ms   : parseFloat(ci.toFixed(3)),
            perVerify_ms: parseFloat(perV.toFixed(4)),
        });
    }

    // -----------------------------------------------------------------------
    // Summary comparison vs SNAP batch verify
    // -----------------------------------------------------------------------
    const snapBatchPath = path.join("results", "bench_batch_verify.json");
    let snapData = null;
    if (fs.existsSync(snapBatchPath)) {
        try {
            snapData = JSON.parse(fs.readFileSync(snapBatchPath)).results;
        } catch { /* ignore */ }
    }

    if (snapData) {
        console.log("\n  Comparison vs SNAP batch Groth16 verify:");
        console.log(`  ${"k".padStart(4)}  ${"SCMS seq (ms)".padStart(14)}  ${"SNAP batch (ms)".padStart(16)}  ${"Ratio SNAP/SCMS".padStart(16)}`);
        console.log("  " + "─".repeat(56));
        for (const r of results) {
            const snap = snapData.find(s => s.k === r.k);
            if (snap) {
                const ratio = snap.batchMs / r.mean_ms;
                console.log(`  ${String(r.k).padStart(4)}  ${r.mean_ms.toFixed(2).padStart(14)}  ${snap.batchMs.toFixed(2).padStart(16)}  ${ratio.toFixed(2).padStart(16)}`);
            }
        }
        console.log("\n  NOTE: SNAP batch is SLOWER than SCMS sequential (expected —");
        console.log("  Groth16 pairings are costlier than ECDSA verify, but SNAP provides");
        console.log("  ZK-unlinkability; within the 1s routine deadline, both meet SLA.");
    }

    // -----------------------------------------------------------------------
    // Save results
    // -----------------------------------------------------------------------
    const output = {
        benchmark   : "scms_sequential_batch_verify",
        description : "SCMS IEEE 1609.2 receiver-side: k sequential ECDSA-P256 verifications",
        method      : "Single pre-generated signature verified k times (isolates crypto cost)",
        hardware    : hw,
        nWarmup     : N_WARMUP,
        nRuns       : N_RUNS,
        timestamp   : new Date().toISOString(),
        results,
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_scms_batch.json");
    fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
    console.log(`\nResults saved → ${outPath}`);
    console.log("Use bench_scms_batch.json to add SCMS column to Table IV.");
}

main();
