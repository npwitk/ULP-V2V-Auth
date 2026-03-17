/**
 * bench_rapidsnark.js
 *
 * Benchmarks the rapidsnark native C++ Groth16 prover against snarkjs.
 *
 * The full prove pipeline has two stages:
 *   Stage 1 — Witness generation   : snarkjs.wtns.calculate (JS/WASM, same for both)
 *   Stage 2 — Groth16 prover       : rapidsnark binary (C++) vs snarkjs (JS/WASM)
 *
 * Reports:
 *   - Witness gen time       (shared by both approaches)
 *   - rapidsnark prove time  (Stage 2 with native binary)
 *   - snarkjs prove time     (Stage 2 with JS, for comparison)
 *   - Total (witness + rapid) vs snarkjs fullProve
 *   - Speedup ratio
 *
 * Prerequisites:
 *   bash scripts/install_rapidsnark.sh
 *
 * Run:  node benchmark/bench_rapidsnark.js
 */

const snarkjs = require("snarkjs");
const fs      = require("fs");
const path    = require("path");
const os      = require("os");
const { execSync, execFileSync } = require("child_process");

// -------------------------------------------------------
// Config
// -------------------------------------------------------
const N_WARMUP = 3;
const N_RUNS   = 10;

const WASM = path.join("build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY = path.join("keys",  "ulp_v2v_auth_final.zkey");
const IN   = path.join("build", "input.json");

// Temp files for rapidsnark I/O (witness file must be binary .wtns)
const TMP_DIR    = os.tmpdir();
const WTNS_PATH  = path.join(TMP_DIR, "ulp_bench.wtns");
const PROOF_PATH = path.join(TMP_DIR, "ulp_proof.json");
const PUB_PATH   = path.join(TMP_DIR, "ulp_public.json");

// -------------------------------------------------------
// Helpers
// -------------------------------------------------------
function detectHardware() {
    if (process.platform === "linux" && fs.existsSync("/proc/cpuinfo")) {
        const cpuinfo = fs.readFileSync("/proc/cpuinfo", "utf8");
        const m = cpuinfo.match(/^Model\s*:\s*(.+)$/m);
        if (m) return m[1].trim();
        const h = cpuinfo.match(/^Hardware\s*:\s*(.+)$/m);
        if (h) return `Linux/${h[1].trim()}`;
    }
    const cpu = os.cpus()[0]?.model ?? "Unknown CPU";
    return `${process.platform === "darwin" ? "macOS" : os.platform()} — ${cpu}`;
}

function findRapidsnark() {
    // 1. PATH
    try { return execSync("which rapidsnark", { stdio: ["pipe","pipe","pipe"] }).toString().trim(); } catch {}
    // 2. Common build locations
    const candidates = [
        "/usr/local/bin/rapidsnark",
        "/usr/local/bin/prover",          // installed name on some builds
        "/usr/bin/rapidsnark",
        "/usr/bin/prover",
        path.join(os.homedir(), "rapidsnark", "build_prover", "src", "prover"),
        path.join(os.homedir(), "rapidsnark", "build_prover", "prover"),
        path.join(os.homedir(), "rapidsnark", "build", "src", "prover"),
        path.join(os.homedir(), "rapidsnark", "build", "prover"),
    ];
    for (const c of candidates) {
        if (fs.existsSync(c)) return c;
    }
    return null;
}

const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
const std  = arr => {
    const m = mean(arr);
    return Math.sqrt(arr.reduce((s, x) => s + (x - m) ** 2, 0) / arr.length);
};

// -------------------------------------------------------
// Main
// -------------------------------------------------------
async function main() {
    // Pre-flight: required files
    for (const f of [WASM, ZKEY, IN]) {
        if (!fs.existsSync(f)) {
            console.error(`Missing: ${f} — run setup + gen-input first.`);
            process.exit(1);
        }
    }

    // Pre-flight: rapidsnark binary
    const rapidsnarkBin = findRapidsnark();
    if (!rapidsnarkBin) {
        console.error("rapidsnark binary not found.");
        console.error("Run:  bash scripts/install_rapidsnark.sh");
        process.exit(1);
    }

    const hw = detectHardware();
    console.log("=".repeat(64));
    console.log("  ULP-V2V-Auth — rapidsnark vs snarkjs Prover Benchmark");
    console.log(`  Hardware     : ${hw}`);
    console.log(`  rapidsnark   : ${rapidsnarkBin}`);
    console.log(`  Warmup runs  : ${N_WARMUP}  |  Measured runs : ${N_RUNS}`);
    console.log("=".repeat(64));

    const input = JSON.parse(fs.readFileSync(IN));

    // -------------------------------------------------------
    // [A] snarkjs fullProve (baseline — as measured before)
    // -------------------------------------------------------
    console.log("\n[A] snarkjs.groth16.fullProve (baseline)...");
    const snarkjsTimes = [];
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const t0 = performance.now();
        await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        const elapsed = performance.now() - t0;
        if (i < N_WARMUP) {
            process.stdout.write(`  warm-up ${i + 1}/${N_WARMUP}: ${elapsed.toFixed(0)} ms\r`);
        } else {
            snarkjsTimes.push(elapsed);
            process.stdout.write(`  run ${i - N_WARMUP + 1}/${N_RUNS}: ${elapsed.toFixed(0)} ms   \r`);
        }
    }
    console.log("");
    const snarkjsMean = mean(snarkjsTimes);
    console.log(`  mean : ${snarkjsMean.toFixed(1)} ms   std : ${std(snarkjsTimes).toFixed(1)} ms`);

    // -------------------------------------------------------
    // [B] Stage 1: Witness generation only (snarkjs, same for both)
    // -------------------------------------------------------
    console.log("\n[B] Stage 1 — Witness generation (snarkjs.wtns.calculate)...");
    const witnessTimesRapid = [];
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const t0 = performance.now();
        await snarkjs.wtns.calculate(input, WASM, { type: "file", fileName: WTNS_PATH });
        const elapsed = performance.now() - t0;
        if (i < N_WARMUP) {
            process.stdout.write(`  warm-up ${i + 1}/${N_WARMUP}: ${elapsed.toFixed(0)} ms\r`);
        } else {
            witnessTimesRapid.push(elapsed);
            process.stdout.write(`  run ${i - N_WARMUP + 1}/${N_RUNS}: ${elapsed.toFixed(0)} ms   \r`);
        }
    }
    console.log("");
    const witnessMean = mean(witnessTimesRapid);
    console.log(`  mean : ${witnessMean.toFixed(1)} ms   std : ${std(witnessTimesRapid).toFixed(1)} ms`);

    // Ensure a fresh witness file exists for the prove step
    await snarkjs.wtns.calculate(input, WASM, { type: "file", fileName: WTNS_PATH });

    // -------------------------------------------------------
    // [C] Stage 2: rapidsnark prove (from precomputed witness)
    // -------------------------------------------------------
    console.log("\n[C] Stage 2 — rapidsnark Groth16 prover...");
    const rapidTimes = [];

    // Warmup
    for (let i = 0; i < N_WARMUP; i++) {
        await snarkjs.wtns.calculate(input, WASM, { type: "file", fileName: WTNS_PATH });
        const t0 = performance.now();
        execFileSync(rapidsnarkBin, [ZKEY, WTNS_PATH, PROOF_PATH, PUB_PATH], { stdio: "pipe" });
        process.stdout.write(`  warm-up ${i + 1}/${N_WARMUP}: ${(performance.now() - t0).toFixed(0)} ms\r`);
    }

    // Measured runs
    for (let i = 0; i < N_RUNS; i++) {
        // Re-generate witness for each run (matches real deployment)
        await snarkjs.wtns.calculate(input, WASM, { type: "file", fileName: WTNS_PATH });
        const t0 = performance.now();
        execFileSync(rapidsnarkBin, [ZKEY, WTNS_PATH, PROOF_PATH, PUB_PATH], { stdio: "pipe" });
        const elapsed = performance.now() - t0;
        rapidTimes.push(elapsed);
        process.stdout.write(`  run ${i + 1}/${N_RUNS}: ${elapsed.toFixed(0)} ms   \r`);
    }
    console.log("");
    const rapidMean = mean(rapidTimes);
    console.log(`  mean : ${rapidMean.toFixed(1)} ms   std : ${std(rapidTimes).toFixed(1)} ms`);

    // Verify rapidsnark proof is valid
    const proof         = JSON.parse(fs.readFileSync(PROOF_PATH));
    const publicSignals = JSON.parse(fs.readFileSync(PUB_PATH));
    const vk            = JSON.parse(fs.readFileSync(path.join("keys", "verification_key.json")));
    const valid         = await snarkjs.groth16.verify(vk, publicSignals, proof);

    // -------------------------------------------------------
    // Summary
    // -------------------------------------------------------
    const totalRapid  = witnessMean + rapidMean;
    const speedupFull = snarkjsMean / totalRapid;
    const speedupProve = (snarkjsMean - witnessTimesRapid[0]) / rapidMean;  // prover-only speedup

    console.log("\n" + "=".repeat(64));
    console.log("  Summary: rapidsnark vs snarkjs");
    console.log("=".repeat(64));
    console.log(`\n  ${"Step".padEnd(30)} ${"snarkjs".padStart(10)} ${"rapidsnark".padStart(12)}`);
    console.log(`  ${"-".repeat(54)}`);
    console.log(`  ${"Witness generation".padEnd(30)} ${(snarkjsMean - mean(snarkjsTimes.map((t,i)=>t)) + witnessTimesRapid[0] || witnessTimesRapid[0] || witnessTimesRapid[0]).toFixed(1).padStart(10)} ms`);

    // Recompute witness-only from snarkjs baseline (estimated as witnessTimesRapid mean)
    const snarkjsProverOnly = snarkjsMean - witnessMean;
    console.log(`  ${"Witness generation".padEnd(30)} ${witnessMean.toFixed(1).padStart(10)} ms  ${witnessMean.toFixed(1).padStart(10)} ms`);
    console.log(`  ${"Groth16 prover".padEnd(30)} ${snarkjsProverOnly.toFixed(1).padStart(10)} ms  ${rapidMean.toFixed(1).padStart(10)} ms`);
    console.log(`  ${"-".repeat(54)}`);
    console.log(`  ${"Total full prove".padEnd(30)} ${snarkjsMean.toFixed(1).padStart(10)} ms  ${totalRapid.toFixed(1).padStart(10)} ms`);
    console.log(`  ${"Speedup (full prove)".padEnd(30)} ${"—".padStart(10)}  ${speedupFull.toFixed(2).padStart(9)}×`);
    console.log(`  ${"Speedup (prover only)".padEnd(30)} ${"—".padStart(10)}  ${(snarkjsProverOnly / rapidMean).toFixed(2).padStart(9)}×`);
    console.log(`\n  Proof valid : ${valid ? "✓ YES" : "✗ NO"}`);

    if (valid) {
        console.log(`\n  Online phase estimate with rapidsnark:`);
        const onlineFrac = 0.043;  // 4.3% message-specific constraints
        console.log(`  Witness bind (4.3% of ${witnessMean.toFixed(1)} ms) : ~${(witnessMean * onlineFrac).toFixed(1)} ms`);
        console.log(`  Prover bind  (4.3% of ${rapidMean.toFixed(1)} ms)  : ~${(rapidMean * onlineFrac).toFixed(1)} ms`);
        console.log(`  Total online (lower bound)         : ~${((witnessMean + rapidMean) * onlineFrac).toFixed(1)} ms`);
        console.log(`  (vs 100 ms BSM cycle → ${(((witnessMean + rapidMean) * onlineFrac) / 100 * 100).toFixed(1)}% budget used)`);
    }

    // -------------------------------------------------------
    // Save results
    // -------------------------------------------------------
    const results = {
        hardware            : hw,
        circuit             : "ULP_V2V_Auth(depth=8)",
        rapidsnarkBinary    : rapidsnarkBin,
        nWarmup             : N_WARMUP,
        nRuns               : N_RUNS,
        timestamp           : new Date().toISOString(),
        proofValid          : valid,
        snarkjsFullProve    : { mean_ms: snarkjsMean,    std_ms: std(snarkjsTimes)        },
        witnessGeneration   : { mean_ms: witnessMean,    std_ms: std(witnessTimesRapid)   },
        rapidsnarkProver    : { mean_ms: rapidMean,      std_ms: std(rapidTimes)          },
        rapidsnarkTotal     : { mean_ms: totalRapid                                       },
        speedupFullProve    : parseFloat(speedupFull.toFixed(3)),
        speedupProverOnly   : parseFloat((snarkjsProverOnly / rapidMean).toFixed(3)),
        onlineEstimate_ms   : parseFloat(((witnessMean + rapidMean) * 0.043).toFixed(2)),
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_rapidsnark.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\nResults saved to ${outPath}`);

    // Cleanup temp files
    for (const f of [WTNS_PATH, PROOF_PATH, PUB_PATH]) {
        if (fs.existsSync(f)) fs.unlinkSync(f);
    }
}

main().catch(err => { console.error(err); process.exit(1); });
