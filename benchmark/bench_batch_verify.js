/**
 * bench_batch_verify.js
 *
 * Compares THREE verification strategies for k proofs:
 *
 *   1. Sequential individual  — k calls to snarkjs.groth16.verify()
 *                               = 3k Miller loops + k final exponentiations
 *
 *   2. TRUE batch verify      — groth16_batch_verify.js
 *                               = (k+3) Miller loops + 1 final exponentiation
 *
 *   3. Theoretical ratio      — (k+3)/(3k) from paper's formula
 *
 * This directly validates whether the theoretical claim holds in practice.
 *
 * Run:  node benchmark/bench_batch_verify.js
 */

const snarkjs  = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { batchVerify, buildBatchCurve } = require("./groth16_batch_verify");
const fs   = require("fs");
const path = require("path");
const os   = require("os");

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

const BATCH_SIZES = [1, 5, 10, 20, 30, 50];
const N_REPEAT    = 3;

const WASM = path.join("build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY = path.join("keys",  "ulp_v2v_auth_final.zkey");
const VK   = path.join("keys",  "verification_key.json");
const IN   = path.join("build", "input.json");

const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;

async function generateProofs(k, baseInput, poseidon) {
    const F = poseidon.F;
    const proofs = [];
    for (let i = 0; i < k; i++) {
        const msg  = BigInt(baseInput.message) + BigInt(i + 1);
        const tCur = BigInt(baseInput.tCurrent);
        const hMsg = F.toObject(poseidon([msg, tCur]));
        const inp  = { ...baseInput, message: msg.toString(), hMessage: hMsg.toString() };
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(inp, WASM, ZKEY);
        proofs.push({ proof, publicSignals });
    }
    return proofs;
}

async function main() {
    for (const f of [WASM, ZKEY, VK, IN]) {
        if (!fs.existsSync(f)) {
            console.error(`Missing: ${f} — run setup + gen-input first.`);
            process.exit(1);
        }
    }

    const baseInput  = JSON.parse(fs.readFileSync(IN));
    const vk         = JSON.parse(fs.readFileSync(VK));
    const poseidon   = await buildPoseidon();
    const batchCurve = await buildBatchCurve();

    console.log("\n" + "=".repeat(72));
    console.log("  ULP-V2V-Auth — True Batch Verification Benchmark");
    console.log("  Sequential (snarkjs) vs Real Batch (groth16_batch_verify.js)");
    console.log("=".repeat(72));

    const allResults = [];

    for (const k of BATCH_SIZES) {
        console.log(`\n[k=${k}] Generating ${k} proof(s)...`);
        const entries = await generateProofs(k, baseInput, poseidon);
        const proofs  = entries.map(e => e.proof);
        const pubSigs = entries.map(e => e.publicSignals);

        // ---- 1. Sequential individual verify ----
        const seqTimes = [];
        for (let r = 0; r < N_REPEAT; r++) {
            const t0 = performance.now();
            for (const { proof, publicSignals } of entries) {
                const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
                if (!ok) throw new Error("Sequential verify failed!");
            }
            seqTimes.push(performance.now() - t0);
        }
        const seqMs = mean(seqTimes);

        // ---- 2. True batch verify ----
        const batchTimes = [];
        let batchValid = false;
        for (let r = 0; r < N_REPEAT; r++) {
            const t0 = performance.now();
            const result = await batchVerify(proofs, pubSigs, vk, batchCurve);
            batchTimes.push(performance.now() - t0);
            batchValid = result.valid;
        }
        const batchMs = mean(batchTimes);

        // ---- 3. Theoretical ----
        const pInd   = 3 * k;
        const pBatch = k + 3;
        const theoreticalSaving = (pInd / pBatch).toFixed(2);
        const actualSaving      = (seqMs / batchMs).toFixed(2);

        console.log(`  Sequential  : ${seqMs.toFixed(1)} ms  (${(seqMs/k).toFixed(1)} ms/proof)`);
        console.log(`  True batch  : ${batchMs.toFixed(1)} ms  [valid=${batchValid}]`);
        console.log(`  Actual saving  : ${actualSaving}×`);
        console.log(`  Theoretical    : ${theoreticalSaving}×  (${pInd} → ${pBatch} pairings)`);

        allResults.push({
            k,
            seqMs, batchMs,
            actualSaving: parseFloat(actualSaving),
            theoreticalSaving: parseFloat(theoreticalSaving),
            pairingsIndividual: pInd,
            pairingsBatch: pBatch,
            batchValid,
        });
    }

    // ---- Summary ----
    console.log("\n" + "=".repeat(72));
    console.log("  Summary: Actual vs Theoretical Saving");
    console.log("=".repeat(72));
    console.log(
        "  k  | Seq (ms) | Batch (ms) | Actual× | Theory× | Valid"
    );
    console.log("  " + "-".repeat(58));
    for (const r of allResults) {
        console.log(
            `  ${String(r.k).padEnd(3)}|` +
            ` ${r.seqMs.toFixed(1).padStart(8)} |` +
            ` ${r.batchMs.toFixed(1).padStart(10)} |` +
            ` ${r.actualSaving.toFixed(2).padStart(7)} |` +
            ` ${r.theoreticalSaving.toFixed(2).padStart(7)} |` +
            `   ${r.batchValid ? "✓" : "✗"}`
        );
    }

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_batch_verify.json");
    fs.writeFileSync(outPath, JSON.stringify({
        hardware: detectHardware(),
        circuit: "ULP_V2V_Auth(depth=8)",
        nRepeat: N_REPEAT,
        timestamp: new Date().toISOString(),
        results: allResults,
    }, null, 2));
    console.log(`\nResults saved to ${outPath}`);
    console.log("Run  npm run plot  to generate figures.");

    await batchCurve.terminate();
}

main().catch(err => { console.error(err); process.exit(1); });
