/**
 * bench_poseidon.js
 *
 * Measures the Poseidon-2 hash time: the irreducible minimum cost
 * of the online authentication phase.
 *
 * In the paper's offline/online decomposition, the online step must
 * at minimum compute:
 *   h_m = Poseidon(message, tCurrent)
 *
 * This is the message-binding operation that cannot be precomputed
 * because the BSM payload (m) and timestamp (tCurrent) are only
 * known at broadcast time.
 *
 * This benchmark provides a direct lower bound on online latency,
 * independent of the snarkjs full-prove pipeline, validating the
 * claim that the online phase is well within the 100 ms BSM cycle.
 *
 * Run:  node benchmark/bench_poseidon.js
 */

const { buildPoseidon } = require("circomlibjs");
const fs   = require("fs");
const path = require("path");
const os   = require("os");

const N_WARMUP = 200;
const N_RUNS   = 5000;   // high count — Poseidon is fast, need many samples
const BATCH    = 1000;   // amortised measurement batch size

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

async function main() {
    const hw = detectHardware();
    console.log("=".repeat(62));
    console.log("  ULP-V2V-Auth — Poseidon-2 Hash Timing");
    console.log("  Online phase lower bound: h_m = Poseidon(msg, tCurrent)");
    console.log(`  Hardware : ${hw}`);
    console.log(`  Warmup   : ${N_WARMUP}  |  Measured runs : ${N_RUNS}`);
    console.log("=".repeat(62));

    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Representative inputs matching real BSM magnitude
    const baseMsg  = BigInt("8317492811234567890");
    const tCurrent = BigInt(Math.floor(Date.now() / 1000));

    // ---- Warmup ----
    console.log("\n[1] Warming up Poseidon...");
    for (let i = 0; i < N_WARMUP; i++) {
        F.toObject(poseidon([baseMsg + BigInt(i), tCurrent]));
    }
    console.log("  Done.");

    // ---- Individual call timing ----
    console.log(`\n[2] Measuring ${N_RUNS} individual Poseidon-2 calls...`);
    const indivTimes = [];
    for (let i = 0; i < N_RUNS; i++) {
        const t0 = performance.now();
        F.toObject(poseidon([baseMsg + BigInt(i), tCurrent]));
        indivTimes.push(performance.now() - t0);
    }
    const indivMean = mean(indivTimes);
    console.log(`  mean : ${indivMean.toFixed(5)} ms   std : ${std(indivTimes).toFixed(5)} ms`);

    // ---- Amortised batch timing (more accurate for fast ops) ----
    console.log(`\n[3] Amortised measurement (batches of ${BATCH})...`);
    const amortTimes = [];
    const N_BATCHES = 30;
    for (let b = 0; b < N_BATCHES; b++) {
        const t0 = performance.now();
        for (let i = 0; i < BATCH; i++) {
            F.toObject(poseidon([baseMsg + BigInt(i), tCurrent]));
        }
        amortTimes.push((performance.now() - t0) / BATCH);
    }
    const amortMean = mean(amortTimes);
    console.log(`  mean : ${amortMean.toFixed(5)} ms   std : ${std(amortTimes).toFixed(5)} ms`);

    // ---- Summary ----
    const bsmCycle     = 100;   // ms
    const percentOfBsm = (amortMean / bsmCycle * 100);

    console.log("\n" + "=".repeat(62));
    console.log("  Summary: Online Phase Lower Bound");
    console.log("=".repeat(62));
    console.log(`  Poseidon-2 (individual)  : ${indivMean.toFixed(4).padStart(9)} ms`);
    console.log(`  Poseidon-2 (amortised)   : ${amortMean.toFixed(4).padStart(9)} ms`);
    console.log(`  BSM cycle budget         :   100.0000 ms`);
    console.log(`  Online cost as % of cycle: ${percentOfBsm.toFixed(4).padStart(9)}%`);
    console.log(`\n  The message-binding step (h_m = Poseidon(m, t)) costs`);
    console.log(`  ${amortMean.toFixed(4)} ms — negligible vs the 100 ms BSM cycle.`);
    console.log(`  This is the irreducible minimum online authentication cost.`);

    const results = {
        hardware         : hw,
        operation        : "Poseidon-2: F.toObject(poseidon([message, tCurrent]))",
        nWarmup          : N_WARMUP,
        nRuns            : N_RUNS,
        batchSize        : BATCH,
        timestamp        : new Date().toISOString(),
        individual       : { mean_ms: indivMean, std_ms: std(indivTimes) },
        amortised        : { mean_ms: amortMean, std_ms: std(amortTimes) },
        bsmCycle_ms      : bsmCycle,
        percentOfBsmCycle: parseFloat(percentOfBsm.toFixed(6)),
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_poseidon.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\nResults saved to ${outPath}`);
    console.log("Run  npm run bench-poseidon  on both Mac and RPi to compare.");
}

main().catch(err => { console.error(err); process.exit(1); });
