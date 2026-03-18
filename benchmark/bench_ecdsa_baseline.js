/**
 * bench_ecdsa_baseline.js
 *
 * Baseline comparison: ECDSA-P256 (as used in IEEE 1609.2 / SCMS) vs
 * ULP-V2V-Auth's online authentication cost (Poseidon-2 hash).
 *
 * In SCMS, every BSM requires:
 *   Sender side : ECDSA-P256 sign(bsm_payload)           ← per-message cost
 *   Receiver side: ECDSA-P256 verify(sig, bsm_payload)   ← per-message cost
 *
 * In ULP-V2V-Auth, the online per-message cost is only:
 *   Sender side : Poseidon-2 hash(bsm_payload, tCurrent) ← 0.377 ms on RPi4
 *   Receiver side: batched Groth16 verify at k+3 pairings ← amortised
 *
 * This benchmark measures ECDSA P-256 sign and verify on the current
 * hardware so the paper can make a direct latency comparison.
 *
 * Uses Node.js built-in `crypto` — no extra dependencies needed.
 *
 * Run:  node benchmark/bench_ecdsa_baseline.js
 */

const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");
const os     = require("os");

// -------------------------------------------------------
// Config
// -------------------------------------------------------
const N_WARMUP = 50;
const N_RUNS   = 500;

// Simulated BSM payload size: position (8B) + velocity (4B) + heading (4B)
// + brake status (1B) + timestamp (8B) + padding = ~250 bytes, matching
// the paper's stated BSM payload size estimate.
const BSM_PAYLOAD = crypto.randomBytes(250);

// -------------------------------------------------------
// Helpers
// -------------------------------------------------------
function detectHardware() {
    if (process.platform === "linux" && fs.existsSync("/proc/cpuinfo")) {
        const cpuinfo = fs.readFileSync("/proc/cpuinfo", "utf8");
        const modelMatch = cpuinfo.match(/^Model\s*:\s*(.+)$/m);
        if (modelMatch) return modelMatch[1].trim();
        const hwMatch = cpuinfo.match(/^Hardware\s*:\s*(.+)$/m);
        if (hwMatch) return `Linux/${hwMatch[1].trim()}`;
    }
    const cpu = os.cpus()[0]?.model ?? "Unknown CPU";
    const platform = process.platform === "darwin" ? "macOS" : os.platform();
    return `${platform} — ${cpu}`;
}

const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
const std  = arr => {
    const m = mean(arr);
    return Math.sqrt(arr.reduce((s, x) => s + (x - m) ** 2, 0) / arr.length);
};

// -------------------------------------------------------
// Main
// -------------------------------------------------------
function main() {
    const hw = detectHardware();
    console.log("=".repeat(64));
    console.log("  ULP-V2V-Auth — ECDSA-P256 Baseline Benchmark");
    console.log("  Comparison: SCMS/ECDSA vs ULP-V2V-Auth online cost");
    console.log(`  Hardware     : ${hw}`);
    console.log(`  BSM payload  : ${BSM_PAYLOAD.length} bytes`);
    console.log(`  Warmup runs  : ${N_WARMUP}  |  Measured runs : ${N_RUNS}`);
    console.log("=".repeat(64));

    // -------------------------------------------------------
    // Step 0: Key generation (one-time setup — for reference only)
    // -------------------------------------------------------
    console.log("\n[0] Key generation (one-time, not per-message)...");
    const keyGenTimes = [];
    for (let i = 0; i < 20; i++) {
        const t0 = performance.now();
        crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
        keyGenTimes.push(performance.now() - t0);
    }
    const keyGenMean = mean(keyGenTimes);
    console.log(`  mean : ${keyGenMean.toFixed(3)} ms   std : ${std(keyGenTimes).toFixed(3)} ms`);

    // Generate a stable key pair for sign/verify benchmarks
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding:  { type: "spki",  format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "der" },
    });
    const privKey = crypto.createPrivateKey({ key: privateKey, format: "der", type: "pkcs8" });
    const pubKey  = crypto.createPublicKey({ key: publicKey,  format: "der", type: "spki"  });

    // Pre-generate a valid signature for the verify benchmark
    const signer = crypto.createSign("SHA256");
    signer.update(BSM_PAYLOAD);
    const validSig = signer.sign(privKey);
    console.log(`  Signature size : ${validSig.length} bytes (DER-encoded)`);

    // -------------------------------------------------------
    // [A] ECDSA Sign — sender per-message cost
    // -------------------------------------------------------
    console.log("\n[A] ECDSA-P256 sign (sender per-message cost)...");

    // Warmup
    for (let i = 0; i < N_WARMUP; i++) {
        const s = crypto.createSign("SHA256");
        s.update(BSM_PAYLOAD);
        s.sign(privKey);
    }

    // Measure
    const signTimes = [];
    for (let i = 0; i < N_RUNS; i++) {
        const t0 = performance.now();
        const s = crypto.createSign("SHA256");
        s.update(BSM_PAYLOAD);
        s.sign(privKey);
        signTimes.push(performance.now() - t0);
        if ((i + 1) % 100 === 0)
            process.stdout.write(`  run ${i + 1}/${N_RUNS}: ${signTimes[i].toFixed(3)} ms   \r`);
    }
    console.log("");
    const signMean = mean(signTimes);
    const signStd  = std(signTimes);
    console.log(`  mean : ${signMean.toFixed(3)} ms   std : ${signStd.toFixed(3)} ms`);

    // -------------------------------------------------------
    // [B] ECDSA Verify — receiver per-message cost
    // -------------------------------------------------------
    console.log("\n[B] ECDSA-P256 verify (receiver per-message cost)...");

    // Warmup
    for (let i = 0; i < N_WARMUP; i++) {
        const v = crypto.createVerify("SHA256");
        v.update(BSM_PAYLOAD);
        v.verify(pubKey, validSig);
    }

    // Measure
    const verifyTimes = [];
    for (let i = 0; i < N_RUNS; i++) {
        const t0 = performance.now();
        const v = crypto.createVerify("SHA256");
        v.update(BSM_PAYLOAD);
        v.verify(pubKey, validSig);
        verifyTimes.push(performance.now() - t0);
        if ((i + 1) % 100 === 0)
            process.stdout.write(`  run ${i + 1}/${N_RUNS}: ${verifyTimes[i].toFixed(3)} ms   \r`);
    }
    console.log("");
    const verifyMean = mean(verifyTimes);
    const verifyStd  = std(verifyTimes);
    console.log(`  mean : ${verifyMean.toFixed(3)} ms   std : ${verifyStd.toFixed(3)} ms`);

    // -------------------------------------------------------
    // [C] Sequential ECDSA verify for k=30 (SCMS dense traffic)
    // -------------------------------------------------------
    console.log("\n[C] Sequential ECDSA verify for k=30 proofs (SCMS dense traffic)...");
    const K = 30;
    const batchVerifyTimes = [];
    for (let run = 0; run < 10; run++) {
        const t0 = performance.now();
        for (let j = 0; j < K; j++) {
            const v = crypto.createVerify("SHA256");
            v.update(BSM_PAYLOAD);
            v.verify(pubKey, validSig);
        }
        batchVerifyTimes.push(performance.now() - t0);
    }
    const ecdsaK30Mean = mean(batchVerifyTimes);
    console.log(`  k=30 sequential ECDSA verify: ${ecdsaK30Mean.toFixed(1)} ms`);

    // -------------------------------------------------------
    // Summary
    // -------------------------------------------------------
    // Reference values from RPi4 measurements (bench_poseidon + bench_rapidsnark)
    const poseidonOnline_ms = 0.377;   // RPi4 measured
    const zkpBatchK30_ms    = 377.8;   // RPi4 measured (batch k=30)
    const zkpPerProof_ms    = zkpBatchK30_ms / K;

    console.log("\n" + "=".repeat(64));
    console.log("  Summary: ECDSA-P256 vs ULP-V2V-Auth (on this hardware)");
    console.log("=".repeat(64));
    console.log(`\n  ${"Operation".padEnd(38)} ${"ECDSA-P256".padStart(12)} ${"ULP-V2V-Auth".padStart(14)}`);
    console.log(`  ${"-".repeat(66)}`);
    console.log(`  ${"Sender per-message cost (ms)".padEnd(38)} ${signMean.toFixed(3).padStart(12)} ${poseidonOnline_ms.toFixed(3).padStart(14)}`);
    console.log(`  ${"Receiver per-message verify (ms)".padEnd(38)} ${verifyMean.toFixed(3).padStart(12)} ${zkpPerProof_ms.toFixed(1).padStart(14)}`);
    console.log(`  ${"k=30 batch verify total (ms)".padEnd(38)} ${ecdsaK30Mean.toFixed(1).padStart(12)} ${"378.0 (RPi4)".padStart(14)}`);
    console.log(`  ${"Auth payload per BSM (bytes)".padEnd(38)} ${"400–600".padStart(12)} ${"224".padStart(14)}`);
    console.log(`  ${"Unlinkability".padEnd(38)} ${"No".padStart(12)} ${"Yes".padStart(14)}`);
    console.log(`\n  Sender speedup  (ULP vs ECDSA sign)   : ${(signMean / poseidonOnline_ms).toFixed(2)}×`);
    console.log(`  Receiver speedup (ULP batch vs ECDSA seq k=30): ${(ecdsaK30Mean / zkpBatchK30_ms).toFixed(2)}×`);

    // -------------------------------------------------------
    // Save results
    // -------------------------------------------------------
    const results = {
        hardware          : hw,
        bsmPayloadBytes   : BSM_PAYLOAD.length,
        signatureBytes    : validSig.length,
        nWarmup           : N_WARMUP,
        nRuns             : N_RUNS,
        timestamp         : new Date().toISOString(),
        keyGeneration     : { mean_ms: keyGenMean,   std_ms: std(keyGenTimes)  },
        ecdsaSign         : { mean_ms: signMean,      std_ms: signStd           },
        ecdsaVerify       : { mean_ms: verifyMean,    std_ms: verifyStd         },
        ecdsaVerifyK30    : { mean_ms: ecdsaK30Mean,  k: K                      },
        // Reference ZKP values from paper (RPi4 measured)
        zkpOnlineRef      : { poseidon_ms: poseidonOnline_ms, source: "bench_poseidon RPi4" },
        zkpBatchRef       : { batchK30_ms: zkpBatchK30_ms,    source: "bench_batch_verify RPi4" },
        senderSpeedup     : parseFloat((signMean / poseidonOnline_ms).toFixed(3)),
        receiverSpeedup   : parseFloat((ecdsaK30Mean / zkpBatchK30_ms).toFixed(3)),
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_ecdsa_baseline.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\nResults saved to ${outPath}`);
}

main();
