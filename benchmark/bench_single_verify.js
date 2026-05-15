/**
 * bench_single_verify.js
 *
 * Measures individual (non-batch) Groth16 proof verification latency
 * using snarkjs on the target OBU-class hardware.
 *
 * Paper claim (Section VI, Experiment 3):
 *   "Emergency-class messages bypass batching and individually verify in
 *    ≈80 ms — well within the 200 ms emergency deadline."
 *
 * Methodology:
 *   - Generate one valid Groth16 proof using the SNAP circuit.
 *   - Discard N_WARMUP warm-up verification calls to stabilise JIT/cache.
 *   - Record N_RUNS consecutive verification latencies.
 *   - Report mean, std, 95% CI, and p5/p95 percentiles.
 *   - Save full run data to results/bench_single_verify.json.
 *
 * Hardware target : Raspberry Pi 4 Model B (ARM Cortex-A72 @ 1.8 GHz)
 * Library         : snarkjs (WASM BN254 backend) — same as batch path
 * Circuit         : ULP-V2V-Auth, depth-16 Merkle tree, 9,746 constraints
 *
 * Run:  node benchmark/bench_single_verify.js
 *       (requires build/ and keys/ from a completed setup + gen-input pass)
 */

"use strict";
const snarkjs = require("snarkjs");
const fs   = require("fs");
const path = require("path");
const os   = require("os");

// ---- Configuration ----
const N_WARMUP = 20;
const N_RUNS   = 500;

const WASM = path.join("build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY = path.join("keys",  "ulp_v2v_auth_final.zkey");
const VK   = path.join("keys",  "verification_key.json");
const IN   = path.join("build", "input.json");

// ---- Utilities ----
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

const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
const std  = arr => {
    const m = mean(arr);
    return Math.sqrt(arr.reduce((s, x) => s + (x - m) ** 2, 0) / arr.length);
};
const ci95 = arr => 1.96 * std(arr) / Math.sqrt(arr.length);
const pctile = (arr, p) => {
    const sorted = [...arr].sort((a, b) => a - b);
    return sorted[Math.floor(p / 100 * sorted.length)];
};

async function main() {
    for (const f of [WASM, ZKEY, VK, IN]) {
        if (!fs.existsSync(f)) {
            console.error(`Missing required file: ${f}`);
            console.error("Run setup and gen-input first, then retry.");
            process.exit(1);
        }
    }

    const hw        = detectHardware();
    const vk        = JSON.parse(fs.readFileSync(VK));
    const baseInput = JSON.parse(fs.readFileSync(IN));

    console.log("=".repeat(64));
    console.log("  SNAP — Individual Groth16 Verification Benchmark");
    console.log("  (Emergency bypass path: single proof, no batching)");
    console.log(`  Hardware   : ${hw}`);
    console.log(`  Circuit    : ULP-V2V-Auth (depth-16 Merkle, 9746 constraints)`);
    console.log(`  Library    : snarkjs WASM BN254 backend`);
    console.log(`  Warm-up    : ${N_WARMUP}   Measured : ${N_RUNS}`);
    console.log("=".repeat(64));

    // Generate one proof (slow, done only once)
    process.stdout.write("\n  Generating proof (one-time, not measured)... ");
    const { proof, publicSignals } =
        await snarkjs.groth16.fullProve(baseInput, WASM, ZKEY);
    console.log("done.");

    // Confirm proof is valid before timing
    const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
    if (!valid) {
        console.error("  ERROR: generated proof failed verification — check keys/circuit.");
        process.exit(1);
    }
    console.log("  Proof valid: ✓\n");

    // ---- Warm-up (discarded) ----
    process.stdout.write(`  Warm-up (${N_WARMUP} runs, discarded)... `);
    for (let i = 0; i < N_WARMUP; i++) {
        await snarkjs.groth16.verify(vk, publicSignals, proof);
    }
    console.log("done.\n");

    // ---- Measured runs ----
    console.log(`  Measuring ${N_RUNS} verification calls...`);
    const times = [];
    for (let i = 0; i < N_RUNS; i++) {
        const t0 = performance.now();
        await snarkjs.groth16.verify(vk, publicSignals, proof);
        times.push(performance.now() - t0);
        if ((i + 1) % 50 === 0) {
            process.stdout.write(
                `  run ${String(i + 1).padStart(3)}/${N_RUNS}: ` +
                `${times[i].toFixed(2)} ms   \r`
            );
        }
    }
    console.log("");

    const m_ms   = mean(times);
    const sd_ms  = std(times);
    const ci_ms  = ci95(times);
    const p5_ms  = pctile(times, 5);
    const p50_ms = pctile(times, 50);
    const p95_ms = pctile(times, 95);

    console.log("\n" + "=".repeat(64));
    console.log("  Individual Groth16 Verify — Results");
    console.log("=".repeat(64));
    console.log(`\n  Mean      : ${m_ms.toFixed(2)} ms`);
    console.log(`  Std dev   : ${sd_ms.toFixed(2)} ms`);
    console.log(`  95% CI    : ± ${ci_ms.toFixed(2)} ms`);
    console.log(`  Median    : ${p50_ms.toFixed(2)} ms`);
    console.log(`  p5 / p95  : ${p5_ms.toFixed(2)} / ${p95_ms.toFixed(2)} ms`);
    console.log(`\n  Emergency deadline : 200 ms`);
    console.log(`  Status : ${m_ms < 200
        ? `✓ PASS — mean ${m_ms.toFixed(0)} ms is within 200 ms emergency deadline`
        : `✗ FAIL — mean ${m_ms.toFixed(0)} ms exceeds 200 ms deadline — update paper`}`);

    console.log(`\n  ==> Update paper Experiment 3 text to:`);
    console.log(`      "individually verify in ≈${m_ms.toFixed(0)} ms ` +
                `(mean of ${N_RUNS} runs, 95% CI ±${ci_ms.toFixed(1)} ms)"`);

    // ---- Save results ----
    const results = {
        benchmark              : "snap_individual_groth16_verify",
        description            : "Single non-batched Groth16 verify — emergency bypass path",
        paper_claim            : "Emergency messages individually verify in ≈80 ms (<200 ms deadline)",
        hardware               : hw,
        library                : "snarkjs (WASM BN254 backend)",
        circuit                : "ULP-V2V-Auth depth-16 Merkle tree (9746 constraints)",
        n_warmup               : N_WARMUP,
        n_runs                 : N_RUNS,
        timestamp              : new Date().toISOString(),
        mean_ms                : parseFloat(m_ms.toFixed(2)),
        std_ms                 : parseFloat(sd_ms.toFixed(2)),
        ci95_ms                : parseFloat(ci_ms.toFixed(2)),
        median_ms              : parseFloat(p50_ms.toFixed(2)),
        p5_ms                  : parseFloat(p5_ms.toFixed(2)),
        p95_ms                 : parseFloat(p95_ms.toFixed(2)),
        emergency_deadline_ms  : 200,
        deadline_met           : m_ms < 200,
        suggested_paper_text   :
            `individually verify in ≈${m_ms.toFixed(0)} ms ` +
            `(mean of ${N_RUNS} runs, 95\\% CI $\\pm${ci_ms.toFixed(1)}$\\,ms)`,
        times_ms               : times.map(t => parseFloat(t.toFixed(2))),
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_single_verify.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\n  Results saved → ${outPath}`);
}

main()
    .then(() => process.exit(0))
    .catch(err => { console.error(err); process.exit(1); });
