/**
 * bench_pairing_breakdown.js
 *
 * Measures the BN254 pairing cost breakdown:
 *   - Miller loop
 *   - Final exponentiation (Fp12 → GT)
 *
 * Validates the paper's claim that final exponentiation constitutes
 * ~78% of pairing cost on Cortex-A72 (vs ~68% on Apple Silicon),
 * explaining why batch verification speedup is larger on RPi 4 than
 * on Apple Silicon: weaker hardware → final exp is proportionally
 * more dominant → amortising it across a batch saves more.
 *
 * Run:  node benchmark/bench_pairing_breakdown.js
 */

const { getCurveFromName } = require("ffjavascript");
const fs   = require("fs");
const path = require("path");
const os   = require("os");

const N_WARMUP = 5;
const N_RUNS   = 20;

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
    console.log("  ULP-V2V-Auth — BN254 Pairing Cost Breakdown");
    console.log(`  Hardware : ${hw}`);
    console.log(`  Warmup   : ${N_WARMUP}  |  Measured runs : ${N_RUNS}`);
    console.log("=".repeat(62));

    const curve = await getCurveFromName("bn128");

    // Use generator points as representative inputs
    const P = curve.G1.g;
    const Q = curve.G2.g;

    // Pre-compute affine forms once (not timed — this is a one-time setup cost)
    const pre1 = curve.prepareG1(P);
    const pre2 = curve.prepareG2(Q);

    // ---- 1. Full pairing (Miller loop + final exp) ----
    console.log("\n[1] Full pairing (Miller loop + final exp)...");
    const fullTimes = [];
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const t0 = performance.now();
        curve.pairing(P, Q);
        const elapsed = performance.now() - t0;
        if (i >= N_WARMUP) fullTimes.push(elapsed);
        else process.stdout.write(`  warm-up ${i + 1}/${N_WARMUP}\r`);
    }
    const fullMean = mean(fullTimes);
    console.log(`  mean : ${fullMean.toFixed(3)} ms   std : ${std(fullTimes).toFixed(3)} ms`);

    // ---- 2. Miller loop only ----
    console.log("\n[2] Miller loop only...");
    const millerTimes = [];
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const t0 = performance.now();
        curve.millerLoop(pre1, pre2);
        const elapsed = performance.now() - t0;
        if (i >= N_WARMUP) millerTimes.push(elapsed);
        else process.stdout.write(`  warm-up ${i + 1}/${N_WARMUP}\r`);
    }
    const millerMean = mean(millerTimes);
    console.log(`  mean : ${millerMean.toFixed(3)} ms   std : ${std(millerTimes).toFixed(3)} ms`);

    // ---- 3. Final exponentiation only ----
    // Compute a real Fp12 element as input (representative of actual pairing output)
    console.log("\n[3] Final exponentiation only...");
    const f_sample = curve.millerLoop(pre1, pre2);
    const finalExpTimes = [];
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const t0 = performance.now();
        curve.finalExponentiation(f_sample);
        const elapsed = performance.now() - t0;
        if (i >= N_WARMUP) finalExpTimes.push(elapsed);
        else process.stdout.write(`  warm-up ${i + 1}/${N_WARMUP}\r`);
    }
    const finalExpMean = mean(finalExpTimes);
    console.log(`  mean : ${finalExpMean.toFixed(3)} ms   std : ${std(finalExpTimes).toFixed(3)} ms`);

    // ---- Summary ----
    const componentTotal  = millerMean + finalExpMean;
    const finalExpPct = (finalExpMean / componentTotal * 100).toFixed(1);
    const millerPct   = (millerMean   / componentTotal * 100).toFixed(1);

    console.log("\n" + "=".repeat(62));
    console.log("  Summary: BN254 Pairing Cost Breakdown");
    console.log("=".repeat(62));
    console.log(`  Miller loop         : ${millerMean.toFixed(3).padStart(8)} ms   (${millerPct}%)`);
    console.log(`  Final exponentiation: ${finalExpMean.toFixed(3).padStart(8)} ms   (${finalExpPct}%)`);
    console.log(`  Sum of components   : ${componentTotal.toFixed(3).padStart(8)} ms`);
    console.log(`  Full pairing        : ${fullMean.toFixed(3).padStart(8)} ms   (includes prepareG1/G2)`);
    console.log(`\n  Final exp share: ${finalExpPct}%`);
    console.log(`  → Batch verify amortises the final exp across k proofs.`);
    console.log(`    Each additional proof adds only 1 Miller loop (~${millerMean.toFixed(1)} ms),`);
    console.log(`    not a full pairing (~${fullMean.toFixed(1)} ms).`);

    const results = {
        hardware           : hw,
        curve              : "BN254 (bn128)",
        nWarmup            : N_WARMUP,
        nRuns              : N_RUNS,
        timestamp          : new Date().toISOString(),
        fullPairing        : { mean_ms: fullMean,     std_ms: std(fullTimes)      },
        millerLoop         : { mean_ms: millerMean,   std_ms: std(millerTimes)    },
        finalExponentiation: { mean_ms: finalExpMean, std_ms: std(finalExpTimes)  },
        finalExpPercent    : parseFloat(finalExpPct),
        millerPercent      : parseFloat(millerPct),
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_pairing_breakdown.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\nResults saved to ${outPath}`);
    console.log("Run  npm run bench-pairing  on both Mac and RPi to compare.");

    await curve.terminate();
}

main().catch(err => { console.error(err); process.exit(1); });
