/**
 * bench_batch_verify.js
 *
 * Benchmarks verification latency for batch sizes k = 1,5,10,20,30,50.
 *
 * For each k:
 *   - Generates k proofs (with slightly different message hashes)
 *   - Measures individual sequential verification (k × single verify)
 *   - Reports theoretical batch cost using the Groth16 batch formula:
 *       Individual: 3k pairings
 *       Batched   : k+3 pairings
 *   - Computes the real time savings factor
 *
 * Note: snarkjs does not implement true batch pairing natively.
 * We measure actual sequential verify time and compare it to the
 * theoretical batched pairing count. This is the standard methodology
 * used in ZKP systems papers (e.g., Bellare et al. 1998 batch verify).
 * The paper cites this analytical formula in Section IV-D.
 *
 * Run:  node benchmark/bench_batch_verify.js
 */

const snarkjs  = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const fs       = require("fs");
const path     = require("path");

// -------------------------------------------------------
// Config
// -------------------------------------------------------
const BATCH_SIZES = [1, 5, 10, 20, 30, 50];
const N_REPEAT    = 5;   // repeat each batch size for stability

const WASM = path.join("build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY = path.join("keys",  "ulp_v2v_auth_final.zkey");
const VK   = path.join("keys",  "verification_key.json");
const IN   = path.join("build", "input.json");

// -------------------------------------------------------
// Pairing operation counts (theoretical)
// -------------------------------------------------------
const pairingsIndividual = k => 3 * k;     // 3 per proof
const pairingsBatch      = k => k + 3;     // Groth16 batch formula

// -------------------------------------------------------
// Generate k proofs with distinct message hashes
// -------------------------------------------------------
async function generateProofs(k, baseInput, poseidon) {
    const F = poseidon.F;
    const proofs = [];
    for (let i = 0; i < k; i++) {
        // Each proof uses a different message (simulates different vehicles/BSMs)
        const msg = BigInt(baseInput.message) + BigInt(i + 1);
        const tCur = BigInt(baseInput.tCurrent);
        const hMsg = F.toObject(poseidon([msg, tCur]));

        const inp = {
            ...baseInput,
            message  : msg.toString(),
            hMessage : hMsg.toString(),
        };
        const { proof, publicSignals } =
            await snarkjs.groth16.fullProve(inp, WASM, ZKEY);
        proofs.push({ proof, publicSignals });
    }
    return proofs;
}

// -------------------------------------------------------
// Measure sequential individual verification for k proofs
// -------------------------------------------------------
async function verifyAll(proofs, vk) {
    const t0 = performance.now();
    for (const { proof, publicSignals } of proofs) {
        const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
        if (!ok) throw new Error("Proof verification failed!");
    }
    return performance.now() - t0;
}

// -------------------------------------------------------
// Main
// -------------------------------------------------------
async function main() {
    for (const f of [WASM, ZKEY, VK, IN]) {
        if (!fs.existsSync(f)) {
            console.error(`Missing: ${f} — run setup + gen-input first.`);
            process.exit(1);
        }
    }

    const baseInput = JSON.parse(fs.readFileSync(IN));
    const vk        = JSON.parse(fs.readFileSync(VK));

    console.log("Building Poseidon for input generation...");
    const poseidon = await buildPoseidon();

    console.log("\n" + "=".repeat(68));
    console.log("  ULP-V2V-Auth — Batch Verification Benchmark");
    console.log("=".repeat(68));
    console.log(`  Batch sizes tested : ${BATCH_SIZES.join(", ")}`);
    console.log(`  Repeats per size   : ${N_REPEAT}`);
    console.log("=".repeat(68));

    const allResults = [];

    for (const k of BATCH_SIZES) {
        console.log(`\n[k=${k}] Generating ${k} proof(s)...`);
        const proofs = await generateProofs(k, baseInput, poseidon);

        const runTimes = [];
        for (let rep = 0; rep < N_REPEAT; rep++) {
            const elapsed = await verifyAll(proofs, vk);
            runTimes.push(elapsed);
            process.stdout.write(`  verify run ${rep + 1}/${N_REPEAT}: ${elapsed.toFixed(1)} ms\r`);
        }
        console.log("");

        const seqMeanMs  = runTimes.reduce((a, b) => a + b, 0) / runTimes.length;
        const perProofMs = seqMeanMs / k;

        // Theoretical pairing counts
        const pInd   = pairingsIndividual(k);   // 3k
        const pBatch = pairingsBatch(k);         // k+3
        const saving = (pInd / pBatch).toFixed(2);

        // Estimated batch time: scale sequential time by pairing ratio
        const batchEstMs = seqMeanMs * (pBatch / pInd);

        console.log(`  Sequential verify : ${seqMeanMs.toFixed(1)} ms  (${perProofMs.toFixed(1)} ms/proof)`);
        console.log(`  Pairings (indiv)  : ${pInd}  →  Batch formula: ${pBatch}  →  ${saving}× saving`);
        console.log(`  Est. batch time   : ${batchEstMs.toFixed(1)} ms`);

        allResults.push({
            k,
            seqMeanMs,
            perProofMs,
            pairingsIndividual : pInd,
            pairingsBatch      : pBatch,
            theoreticalSaving  : parseFloat(saving),
            batchEstMs,
        });
    }

    // -------------------------------------------------------
    // Summary table
    // -------------------------------------------------------
    console.log("\n" + "=".repeat(68));
    console.log("  Summary Table (matches paper Section V / Fig. batch_throughput)");
    console.log("=".repeat(68));
    console.log(
        "  k  | Seq verify (ms) | ms/proof | Pairs(ind) | Pairs(batch) | ×saving"
    );
    console.log("  " + "-".repeat(64));
    for (const r of allResults) {
        console.log(
            `  ${String(r.k).padEnd(3)}|` +
            ` ${r.seqMeanMs.toFixed(1).padStart(15)}  |` +
            ` ${r.perProofMs.toFixed(2).padStart(8)} |` +
            ` ${String(r.pairingsIndividual).padStart(10)} |` +
            ` ${String(r.pairingsBatch).padStart(12)} |` +
            ` ${r.theoreticalSaving.toFixed(2).padStart(7)}`
        );
    }

    // -------------------------------------------------------
    // Save results
    // -------------------------------------------------------
    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_batch_verify.json");
    fs.writeFileSync(outPath, JSON.stringify({
        hardware    : "Mac (run on device)",
        circuit     : "ULP_V2V_Auth(depth=8)",
        nRepeat     : N_REPEAT,
        timestamp   : new Date().toISOString(),
        results     : allResults,
    }, null, 2));
    console.log(`\nResults saved to ${outPath}`);
    console.log("Run  npm run plot  to generate figures.");
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
