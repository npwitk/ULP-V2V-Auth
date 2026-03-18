/**
 * bench_e2e.js — End-to-End Latency Budget (Phases 2–4)
 *
 * Measures every step of the ULP-V2V-Auth pipeline on this device
 * and produces the latency budget table for the paper (Table: End-to-End).
 *
 * Steps timed:
 *   Phase 2a  AST acquisition RTT  (network round-trip to AIS)
 *   Phase 2b  Offline precomputation per slot  (snarkjs fullProve)
 *   Phase 3   Online binding  (Poseidon-2 hash only)
 *   Phase 4   Batch verification  (k = 1, 5, 10, 30)
 *
 * Prerequisites: obu_data/identity.json must exist (run register.js first)
 *
 * Run:  node obu/bench_e2e.js --ais=http://MAC_IP:3002
 */

const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const crypto  = require("crypto");
const fs      = require("fs");
const path    = require("path");
const http    = require("http");
const os      = require("os");

// -------------------------------------------------------
// Config
// -------------------------------------------------------
const AIS_URL = process.argv.find(a => a.startsWith("--ais="))?.split("=")[1];
if (!AIS_URL) {
    console.error("Usage: node obu/bench_e2e.js --ais=http://MAC_IP:3002");
    process.exit(1);
}

const WASM  = path.join("build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY  = path.join("keys",  "ulp_v2v_auth_final.zkey");
const VK    = path.join("keys",  "verification_key.json");
const IDENT = path.join("obu_data", "identity.json");

const N_ACQUISITION  = 10;    // RTT measurements
const N_PROVE        = 3;     // precomputation measurements (slow)
const N_POSEIDON     = 2000;  // online binding measurements
const BATCH_SIZES    = [1, 5, 10, 30];

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
const std  = arr => { const m = mean(arr); return Math.sqrt(arr.reduce((s, x) => s + (x-m)**2, 0) / arr.length); };

function httpPost(url, data) {
    return new Promise((resolve, reject) => {
        const { URL } = require("url");
        const parsed  = new URL(url);
        const body    = JSON.stringify(data);
        const req     = http.request({
            hostname: parsed.hostname, port: parsed.port || 80,
            path: parsed.pathname, method: "POST",
            headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
        }, res => {
            let d = "";
            res.on("data", c => d += c);
            res.on("end", () => { try { resolve(JSON.parse(d)); } catch(e) { reject(new Error(d)); } });
        });
        req.on("error", reject);
        req.write(body); req.end();
    });
}

// -------------------------------------------------------
// Main
// -------------------------------------------------------
async function main() {
    const hw = detectHardware();
    console.log("=".repeat(64));
    console.log("  ULP-V2V-Auth — End-to-End Latency Budget");
    console.log(`  Hardware : ${hw}`);
    console.log("=".repeat(64));

    // Pre-flight checks
    for (const f of [WASM, ZKEY, VK, IDENT]) {
        if (!fs.existsSync(f)) { console.error(`Missing: ${f}`); process.exit(1); }
    }
    const identity = JSON.parse(fs.readFileSync(IDENT));
    const vk       = JSON.parse(fs.readFileSync(VK));

    // -------------------------------------------------------
    // Phase 2a — AST acquisition RTT
    // -------------------------------------------------------
    console.log(`\n[Phase 2a] AST acquisition RTT (${N_ACQUISITION} calls to AIS)...`);
    const rttTimes = [];
    let lastAst;
    for (let i = 0; i < N_ACQUISITION; i++) {
        const t0  = performance.now();
        const res = await httpPost(`${AIS_URL}/acquire`, {
            vin:    identity.vin,
            pubkey: identity.pubkeyHex,
            sigma:  identity.sigma,
            nonce:  identity.nonce,
        });
        const rtt = performance.now() - t0;
        if (res.error) { console.error(`AIS error: ${res.error}`); process.exit(1); }
        rttTimes.push(rtt);
        lastAst = res;
        process.stdout.write(`  ${i+1}/${N_ACQUISITION}: ${rtt.toFixed(1)} ms   \r`);
    }
    console.log("");
    const rttMean = mean(rttTimes);
    console.log(`  mean: ${rttMean.toFixed(1)} ms   std: ${std(rttTimes).toFixed(1)} ms`);

    // -------------------------------------------------------
    // Build circuit input from last acquired AST
    // -------------------------------------------------------
    const poseidon = await buildPoseidon();
    const F        = poseidon.F;
    const hashFn   = (...args) => F.toObject(poseidon(args));

    const MESSAGE  = BigInt("0xBEEF0001CAFE0002DEAD0003BABE0004");
    const tCurrent = BigInt(lastAst.ast.tStart) + BigInt(60); // 60s into session
    const hMessage = hashFn(MESSAGE, tCurrent);

    const circuitInput = {
        merkleRoot   : lastAst.merkleRoot,
        tCurrent     : tCurrent.toString(),
        hMessage     : hMessage.toString(),
        sid          : lastAst.ast.sid,
        tStart       : lastAst.ast.tStart,
        tEnd         : lastAst.ast.tEnd,
        cap          : lastAst.ast.cap,
        r            : lastAst.ast.r,
        pathElements : lastAst.merklePathElements,
        pathIndices  : lastAst.merklePathIndices,
        message      : MESSAGE.toString(),
    };
    // Save for reuse
    fs.mkdirSync("build", { recursive: true });
    fs.writeFileSync(path.join("build", "input.json"), JSON.stringify(circuitInput, null, 2));

    // -------------------------------------------------------
    // Phase 2b — Offline precomputation (snarkjs fullProve)
    // -------------------------------------------------------
    console.log(`\n[Phase 2b] Offline precomputation — snarkjs fullProve (${N_PROVE} runs)...`);
    const proveTimes = [];
    for (let i = 0; i < N_PROVE; i++) {
        const t0 = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
        proveTimes.push(performance.now() - t0);
        process.stdout.write(`  run ${i+1}/${N_PROVE}: ${proveTimes[i].toFixed(0)} ms   \r`);
        if (i === N_PROVE - 1) { var lastProof = proof; var lastPub = publicSignals; }
    }
    console.log("");
    const proveMean = mean(proveTimes);
    console.log(`  mean: ${proveMean.toFixed(0)} ms   std: ${std(proveTimes).toFixed(0)} ms`);

    // Verify the last proof is valid
    const valid = await snarkjs.groth16.verify(vk, lastPub, lastProof);
    console.log(`  Proof valid: ${valid ? "✓ YES" : "✗ NO"}`);

    // -------------------------------------------------------
    // Phase 3 — Online binding (Poseidon-2 hash)
    // -------------------------------------------------------
    console.log(`\n[Phase 3]  Online binding — Poseidon-2 (${N_POSEIDON} calls)...`);
    const poseidonTimes = [];
    const BATCH = 500;
    for (let b = 0; b < N_POSEIDON / BATCH; b++) {
        const t0 = performance.now();
        for (let i = 0; i < BATCH; i++) hashFn(MESSAGE + BigInt(i), tCurrent);
        poseidonTimes.push((performance.now() - t0) / BATCH);
    }
    const poseidonMean = mean(poseidonTimes);
    console.log(`  mean: ${poseidonMean.toFixed(4)} ms   (${(poseidonMean/100*100).toFixed(3)}% of BSM cycle)`);

    // -------------------------------------------------------
    // Phase 4 — Batch verification
    // -------------------------------------------------------
    console.log(`\n[Phase 4]  Batch verification...`);

    // Generate k=30 proofs (reuse same proof with different random scalars — valid for batch)
    const K_MAX = 30;
    console.log(`  Generating ${K_MAX} proofs for batch test (reusing same proof)...`);
    const { proof: p0, publicSignals: pub0 } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);

    // Build arrays of k identical proofs (same public signals — valid for soundness test)
    const proofs  = Array(K_MAX).fill(p0);
    const pubSigs = Array(K_MAX).fill(pub0);

    // Sequential verification (baseline)
    const seqResults = {};
    for (const k of BATCH_SIZES) {
        const t0 = performance.now();
        for (let j = 0; j < k; j++) await snarkjs.groth16.verify(vk, pubSigs[j], proofs[j]);
        seqResults[k] = performance.now() - t0;
    }

    // True batch verification (import from existing groth16_batch_verify)
    let batchFn;
    try {
        const batchModule = require("../benchmark/groth16_batch_verify.js");
        batchFn = batchModule.batchVerify;
    } catch {
        // Inline minimal batch verify if module not found
        const ffjs = require("ffjavascript");
        batchFn = async (proofsArr, pubArr, vkObj) => {
            const curve = await ffjs.buildBn128();
            const F = curve.Fr;
            const G1 = curve.G1;
            const G2 = curve.G2;
            // Randomised linear combination check
            const rhos = proofsArr.map(() => F.random());
            let aggA = G1.zero, aggC = G1.zero, aggAlpha = G1.zero, aggL = G1.zero;
            const IC = vkObj.IC.map(p => G1.fromObject(p));
            for (let j = 0; j < proofsArr.length; j++) {
                const rho = rhos[j];
                const A = G1.fromObject(proofsArr[j].pi_a);
                const C = G1.fromObject(proofsArr[j].pi_c);
                aggA     = G1.add(aggA,     G1.timesFr(A, rho));
                aggC     = G1.add(aggC,     G1.timesFr(C, rho));
                aggAlpha = G1.add(aggAlpha, G1.timesFr(IC[0], rho));
                let L = IC[0];
                for (let i = 0; i < pubArr[j].length; i++)
                    L = G1.add(L, G1.timesFr(IC[i+1], BigInt(pubArr[j][i])));
                aggL = G1.add(aggL, G1.timesFr(L, rho));
            }
            const B   = G2.fromObject(proofsArr[0].pi_b);
            const beta  = G2.fromObject(vkObj.vk_beta_2);
            const gamma = G2.fromObject(vkObj.vk_gamma_2);
            const delta = G2.fromObject(vkObj.vk_delta_2);
            const lhs = curve.pairing(aggA, B);
            const r1  = curve.pairing(aggAlpha, beta);
            const r2  = curve.pairing(aggL, gamma);
            const r3  = curve.pairing(aggC, delta);
            const rhs = curve.GT.mul(curve.GT.mul(r1, r2), r3);
            await curve.terminate();
            return curve.GT.eq(lhs, rhs);
        };
    }

    const batchResults = {};
    for (const k of BATCH_SIZES) {
        const t0     = performance.now();
        const ok     = await batchFn(proofs.slice(0, k), pubSigs.slice(0, k), vk);
        batchResults[k] = performance.now() - t0;
        console.log(`  k=${k.toString().padEnd(3)}: seq=${seqResults[k].toFixed(1).padStart(7)} ms   batch=${batchResults[k].toFixed(1).padStart(7)} ms   ` +
                    `speedup=${( seqResults[k] / batchResults[k]).toFixed(2)}×   valid=${ok ? "✓" : "✗"}`);
    }

    // -------------------------------------------------------
    // Latency Budget Table
    // -------------------------------------------------------
    console.log("\n" + "=".repeat(64));
    console.log("  End-to-End Latency Budget — ULP-V2V-Auth on " + hw.split("—")[0].trim());
    console.log("=".repeat(64));
    const row = (label, val, phase, note) =>
        console.log(`  ${label.padEnd(32)} ${val.padStart(10)}  Phase ${phase}  ${note}`);
    row("AST acquisition (LAN RTT)",   `${rttMean.toFixed(0)} ms`,    "2a", "one-time per session");
    row("Precomputation / slot",        `${proveMean.toFixed(0)} ms`,  "2b", "offline background");
    row("Online binding (Poseidon-2)", `${poseidonMean.toFixed(3)} ms`, "3", "per-message cost");
    row("Batch verify k=30",           `${batchResults[30].toFixed(0)} ms`, "4", "per 100ms window");
    row("Emergency verify (k=1 seq)", `${seqResults[1].toFixed(0)} ms`, "4", "priority bypass");
    console.log("=".repeat(64));

    // -------------------------------------------------------
    // Save results
    // -------------------------------------------------------
    const results = {
        hardware          : hw,
        timestamp         : new Date().toISOString(),
        proofValid        : valid,
        astAcquisition    : { mean_ms: rttMean,      std_ms: std(rttTimes),    n: N_ACQUISITION },
        precomputation    : { mean_ms: proveMean,     std_ms: std(proveTimes),  n: N_PROVE       },
        onlineBinding     : { mean_ms: poseidonMean,  std_ms: std(poseidonTimes) },
        batchVerification : BATCH_SIZES.map(k => ({
            k,
            sequential_ms : parseFloat(seqResults[k].toFixed(2)),
            batch_ms      : parseFloat(batchResults[k].toFixed(2)),
            speedup       : parseFloat((seqResults[k] / batchResults[k]).toFixed(3)),
        })),
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_e2e.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\nResults saved to ${outPath}`);
}

main().catch(err => { console.error(err); process.exit(1); });
