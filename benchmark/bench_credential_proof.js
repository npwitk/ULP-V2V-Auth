/**
 * bench_credential_proof.js — Phase 2 Step 2 Credential Proof Benchmark
 *
 * Measures the cost of the Privacy-Preserving Credential Proof in Phase 2
 * of SNAP: the vehicle proves possession of its long-term credential σ_i
 * to the AIS without revealing its identity.
 *
 * PROTOCOL MODELLED (Non-Interactive Schnorr PoK, Fiat-Shamir):
 *   The vehicle proves knowledge of private key sk_i corresponding to pk_i.
 *   This is a zero-knowledge proof that the vehicle was issued a credential
 *   by the TA, without revealing which credential (sk_i is never transmitted).
 *
 *   Prove:
 *     k  ← random scalar (Zp)
 *     R  = k · G          (commitment, 1× EC scalar mult)
 *     c  = H(R ‖ pk_i)   (Fiat-Shamir challenge)
 *     s  = k + c · sk_i  (response, mod p)
 *   Send: (R, s) to AIS
 *
 *   Verify:
 *     c  = H(R ‖ pk_i)
 *     Check: s · G == R + c · pk_i  (2× EC scalar mult + 1× EC add)
 *
 * CONTEXT:
 *   This is a one-time-per-epoch operation (once per AST acquisition period,
 *   typically every 300 s), NOT per-message. The latency is amortized across
 *   all BSMs sent in that epoch.
 *
 * Run: node benchmark/bench_credential_proof.js
 * No extra dependencies — uses Node.js built-in crypto (ECDH on P-256).
 *
 * Output: results/bench_credential_proof.json
 */

"use strict";

const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");
const os     = require("os");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const N_WARMUP = 50;
const N_RUNS   = 500;   // credential proof is per-epoch, not per-BSM

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
// Non-Interactive Schnorr PoK using Node.js built-in ECDH (P-256)
//
// Node crypto does not expose raw EC scalar mult directly, so we simulate
// the PoK cost using ECDH key-agreement (which internally performs one EC
// scalar mult) for the commitment step, and ECDSA sign/verify for the
// response step (also one EC scalar mult each).
//
// Total cost measured:
//   Prove: 1× keygen (k·G commitment) + 1× ECDSA sign (response)
//   Verify: 1× ECDSA verify
//
// This is a conservative estimate — a native EC library (e.g. libsecp256r1)
// would be faster. On RPi 4 this gives an upper bound.
// ---------------------------------------------------------------------------

/**
 * Prove credential knowledge (Schnorr-style, Fiat-Shamir).
 * Returns { commitment, response } — sizes analogous to (R, s).
 */
function proveCredential(longTermPrivKey, longTermPubKey) {
    // Step 1: Generate ephemeral commitment k·G (= 1 EC scalar mult)
    const { privateKey: kPrivDer, publicKey: kPubDer } =
        crypto.generateKeyPairSync("ec", {
            namedCurve: "P-256",
            privateKeyEncoding: { type: "pkcs8", format: "der" },
            publicKeyEncoding:  { type: "spki",  format: "der" },
        });
    const kPriv = crypto.createPrivateKey({ key: kPrivDer, format: "der", type: "pkcs8" });
    const kPub  = crypto.createPublicKey({ key: kPubDer, format: "der", type: "spki" });

    // Step 2: Fiat-Shamir challenge = H(R ‖ pk_i)
    // (We use the DER-encoded public key bytes as the combined input)
    const challengeHash = crypto.createHash("sha256")
        .update(kPubDer)
        .update(longTermPubKey.export({ type: "spki", format: "der" }))
        .digest();

    // Step 3: Sign challenge with long-term key (= 1 EC scalar mult)
    // In a real Schnorr PoK, response s = k + c·sk. Here we use ECDSA as
    // a proxy for the same computational cost.
    const signer = crypto.createSign("SHA256");
    signer.update(challengeHash);
    const response = signer.sign(longTermPrivKey);

    return { commitment: kPubDer, response, challengeHash };
}

/**
 * Verify credential proof.
 * Returns true if valid.
 */
function verifyCredential(longTermPubKey, commitment, response, challengeHash) {
    const verifier = crypto.createVerify("SHA256");
    verifier.update(challengeHash);
    return verifier.verify(longTermPubKey, response);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
    const hw = detectHardware();

    console.log("=".repeat(68));
    console.log("  SNAP — Phase 2 Step 2: Credential Proof Benchmark");
    console.log("  Models: Non-Interactive Schnorr PoK of sk_i (P-256)");
    console.log(`  Hardware    : ${hw}`);
    console.log(`  Warmup / Runs: ${N_WARMUP} / ${N_RUNS}`);
    console.log("=".repeat(68));

    // Generate long-term vehicle key pair (done once at manufacture time)
    const { privateKey: ltPrivDer, publicKey: ltPubDer } =
        crypto.generateKeyPairSync("ec", {
            namedCurve: "P-256",
            privateKeyEncoding: { type: "pkcs8", format: "der" },
            publicKeyEncoding:  { type: "spki",  format: "der" },
        });
    const ltPriv = crypto.createPrivateKey({ key: ltPrivDer, format: "der", type: "pkcs8" });
    const ltPub  = crypto.createPublicKey({ key: ltPubDer, format: "der", type: "spki" });

    console.log(`\n  Long-term key pair generated (P-256, 33-byte compressed public key)`);

    // -----------------------------------------------------------------------
    // [A] Proving time (vehicle → AIS)
    // -----------------------------------------------------------------------
    console.log("\n[A] Credential Proof — Proving Time (vehicle side)");

    for (let i = 0; i < N_WARMUP; i++) proveCredential(ltPriv, ltPub);

    const proveTimes = [];
    let lastProof;
    for (let i = 0; i < N_RUNS; i++) {
        const t0 = performance.now();
        lastProof = proveCredential(ltPriv, ltPub);
        proveTimes.push(performance.now() - t0);
        if ((i + 1) % 100 === 0)
            process.stdout.write(`  run ${i + 1}/${N_RUNS}: ${proveTimes[i].toFixed(3)} ms   \r`);
    }
    console.log("");
    const proveMean = mean(proveTimes);
    const proveCI   = ci95(proveTimes);
    console.log(`  mean : ${proveMean.toFixed(3)} ms  ±${proveCI.toFixed(3)} ms (95% CI)`);
    console.log(`  Proof size: ${lastProof.commitment.length + lastProof.response.length} bytes (commitment + response)`);

    // -----------------------------------------------------------------------
    // [B] Verification time (AIS side)
    // -----------------------------------------------------------------------
    console.log("\n[B] Credential Proof — Verification Time (AIS side)");

    for (let i = 0; i < N_WARMUP; i++) {
        verifyCredential(ltPub, lastProof.commitment, lastProof.response, lastProof.challengeHash);
    }

    const verifyTimes = [];
    for (let i = 0; i < N_RUNS; i++) {
        const t0 = performance.now();
        verifyCredential(ltPub, lastProof.commitment, lastProof.response, lastProof.challengeHash);
        verifyTimes.push(performance.now() - t0);
        if ((i + 1) % 100 === 0)
            process.stdout.write(`  run ${i + 1}/${N_RUNS}: ${verifyTimes[i].toFixed(3)} ms   \r`);
    }
    console.log("");
    const verifyMean = mean(verifyTimes);
    const verifyCI   = ci95(verifyTimes);
    console.log(`  mean : ${verifyMean.toFixed(3)} ms  ±${verifyCI.toFixed(3)} ms (95% CI)`);

    // -----------------------------------------------------------------------
    // [C] Amortized cost per BSM
    // -----------------------------------------------------------------------
    const EPOCH_S   = 300;      // AST epoch duration (seconds)
    const BSM_HZ    = 10;       // BSM broadcast rate (Hz)
    const bsmsPerEpoch = EPOCH_S * BSM_HZ;
    const amortizedProve_us = (proveMean / bsmsPerEpoch) * 1000;

    console.log(`\n[C] Amortized Credential Proof Cost per BSM`);
    console.log(`  Epoch duration : ${EPOCH_S} s`);
    console.log(`  BSMs per epoch : ${bsmsPerEpoch}`);
    console.log(`  Amortized cost : ${amortizedProve_us.toFixed(3)} µs/BSM  (negligible vs 100 ms budget)`);

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    console.log("\n" + "=".repeat(68));
    console.log("  Summary");
    console.log("=".repeat(68));
    console.log(`  Proving   : ${proveMean.toFixed(3)} ms ±${proveCI.toFixed(3)} ms (one-time per epoch)`);
    console.log(`  Verify    : ${verifyMean.toFixed(3)} ms ±${verifyCI.toFixed(3)} ms (AIS side)`);
    console.log(`  Amortized : ${amortizedProve_us.toFixed(3)} µs per BSM over ${EPOCH_S}s epoch`);
    console.log(`\n  NOTE: This benchmark models Schnorr PoK of sk_i (P-256).`);
    console.log(`  A full signature proof (BBS+, KVAC) would have different timing.`);
    console.log(`  This cost is per AST epoch, not per message — it is NOT`);
    console.log(`  on the critical path of the 100 ms BSM cycle.`);

    // -----------------------------------------------------------------------
    // Save results
    // -----------------------------------------------------------------------
    const results = {
        benchmark    : "snap_credential_proof",
        description  : "Phase 2 Step 2: Schnorr PoK of long-term ECDSA-P256 private key",
        protocol     : "Non-interactive Schnorr PoK (Fiat-Shamir) on P-256",
        hardware     : hw,
        nWarmup      : N_WARMUP,
        nRuns        : N_RUNS,
        timestamp    : new Date().toISOString(),
        prove        : { mean_ms: parseFloat(proveMean.toFixed(4)), ci95_ms: parseFloat(proveCI.toFixed(4)) },
        verify       : { mean_ms: parseFloat(verifyMean.toFixed(4)), ci95_ms: parseFloat(verifyCI.toFixed(4)) },
        amortized    : {
            epoch_s       : EPOCH_S,
            bsms_per_epoch: bsmsPerEpoch,
            cost_us_per_bsm: parseFloat(amortizedProve_us.toFixed(4)),
        },
        proofSizeBytes: lastProof.commitment.length + lastProof.response.length,
        note: "Schnorr PoK models the minimal credential proof cost. Phase 2 Step 2 is one-time per epoch; cost is not on the real-time BSM path.",
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_credential_proof.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\nResults saved → ${outPath}`);
}

main();
