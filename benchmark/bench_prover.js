/**
 * bench_prover.js
 *
 * Benchmarks Groth16 proof generation over N repeated runs.
 * Reports: mean, std dev, min, max latency.
 * Saves results to results/bench_prover.json  (for plotting).
 *
 * This measures the FULL prove time (offline phase).
 * It also measures WITNESS-ONLY time as a proxy for the
 * "online phase" cost (binding a new message hash to a
 * precomputed partial witness).
 *
 * Run:  node benchmark/bench_prover.js
 */

const snarkjs = require("snarkjs");
const fs      = require("fs");
const path    = require("path");
const os      = require("os");

/**
 * Detect hardware description automatically.
 * On Raspberry Pi, /proc/cpuinfo contains "Model : Raspberry Pi ..."
 * On macOS, os.cpus()[0].model has the chip name.
 */
function detectHardware() {
    // Raspberry Pi (Linux): read /proc/cpuinfo for the Model line
    if (process.platform === "linux" && fs.existsSync("/proc/cpuinfo")) {
        const cpuinfo = fs.readFileSync("/proc/cpuinfo", "utf8");
        const modelMatch = cpuinfo.match(/^Model\s*:\s*(.+)$/m);
        if (modelMatch) return modelMatch[1].trim();
        // Fallback: use Hardware field
        const hwMatch = cpuinfo.match(/^Hardware\s*:\s*(.+)$/m);
        if (hwMatch) return `Linux/${hwMatch[1].trim()}`;
    }
    // macOS / generic: use OS + CPU model
    const cpu = os.cpus()[0]?.model ?? "Unknown CPU";
    const platform = process.platform === "darwin" ? "macOS" : os.platform();
    return `${platform} — ${cpu}`;
}

// -------------------------------------------------------
// Config
// -------------------------------------------------------
const N_WARMUP = 3;   // discarded runs (JIT warm-up)
const N_RUNS   = 20;  // measured runs

const WASM = path.join("build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY = path.join("keys",  "ulp_v2v_auth_final.zkey");
const IN   = path.join("build", "input.json");

// -------------------------------------------------------
// Stats helpers
// -------------------------------------------------------
const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
const std  = arr => {
    const m = mean(arr);
    return Math.sqrt(arr.reduce((s, x) => s + (x - m) ** 2, 0) / arr.length);
};

function printStats(label, times) {
    console.log(`\n  ${label}`);
    console.log(`    mean : ${mean(times).toFixed(2)} ms`);
    console.log(`    std  : ${std(times).toFixed(2)} ms`);
    console.log(`    min  : ${Math.min(...times).toFixed(2)} ms`);
    console.log(`    max  : ${Math.max(...times).toFixed(2)} ms`);
}

async function main() {
    for (const f of [WASM, ZKEY, IN]) {
        if (!fs.existsSync(f)) {
            console.error(`Missing: ${f} — run setup + gen-input first.`);
            process.exit(1);
        }
    }

    const input = JSON.parse(fs.readFileSync(IN));

    console.log("=".repeat(52));
    console.log("  ULP-V2V-Auth — Prover Latency Benchmark");
    console.log(`  Warmup runs : ${N_WARMUP}  |  Measured runs : ${N_RUNS}`);
    console.log("=".repeat(52));

    // -------------------------------------------------------
    // Benchmark 1: Full prove (offline phase)
    //   witness generation + Groth16 prover
    // -------------------------------------------------------
    console.log("\n[1] Full proof generation (offline phase)...");
    const fullTimes = [];
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const t0 = performance.now();
        await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        const elapsed = performance.now() - t0;

        if (i < N_WARMUP) {
            process.stdout.write(`  warm-up ${i + 1}/${N_WARMUP}: ${elapsed.toFixed(0)} ms\r`);
        } else {
            fullTimes.push(elapsed);
            process.stdout.write(
                `  run ${i - N_WARMUP + 1}/${N_RUNS}: ${elapsed.toFixed(0)} ms   \r`
            );
        }
    }
    console.log("");
    printStats("Full prove (offline phase)", fullTimes);

    // -------------------------------------------------------
    // Benchmark 2: Witness generation only (approximates online phase)
    //   In the paper's model, the precomputed partial witness
    //   is reused; only the message-specific part is freshly computed.
    //   snarkjs exposes witness calculation separately as:
    //     snarkjs.wtns.calculate(input, wasm) → witness buffer
    // -------------------------------------------------------
    console.log("\n[2] Witness generation only (online-phase proxy)...");
    const witnessOnlyTimes = [];
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const t0 = performance.now();
        await snarkjs.wtns.calculate(input, WASM, { type: "mem" });
        const elapsed = performance.now() - t0;

        if (i < N_WARMUP) {
            process.stdout.write(`  warm-up ${i + 1}/${N_WARMUP}: ${elapsed.toFixed(0)} ms\r`);
        } else {
            witnessOnlyTimes.push(elapsed);
            process.stdout.write(
                `  run ${i - N_WARMUP + 1}/${N_RUNS}: ${elapsed.toFixed(0)} ms   \r`
            );
        }
    }
    console.log("");
    printStats("Witness generation (online-phase proxy)", witnessOnlyTimes);

    // -------------------------------------------------------
    // Save results
    // -------------------------------------------------------
    fs.mkdirSync("results", { recursive: true });
    const results = {
        hardware    : detectHardware(),
        circuit     : "ULP_V2V_Auth(depth=8, constraints=5069)",
        nWarmup     : N_WARMUP,
        nRuns       : N_RUNS,
        timestamp   : new Date().toISOString(),
        fullProve   : {
            times_ms : fullTimes,
            mean_ms  : mean(fullTimes),
            std_ms   : std(fullTimes),
            min_ms   : Math.min(...fullTimes),
            max_ms   : Math.max(...fullTimes),
        },
        witnessOnly : {
            times_ms : witnessOnlyTimes,
            mean_ms  : mean(witnessOnlyTimes),
            std_ms   : std(witnessOnlyTimes),
            min_ms   : Math.min(...witnessOnlyTimes),
            max_ms   : Math.max(...witnessOnlyTimes),
        },
    };
    const outPath = path.join("results", "bench_prover.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\nResults saved to ${outPath}`);

    // Show RPi estimate only when running on a non-RPi device
    const hw = detectHardware();
    if (!hw.toLowerCase().includes("raspberry")) {
        console.log("\n" + "=".repeat(52));
        console.log("  RPi 4 Estimate (×6–8 slowdown on Cortex-A72)");
        console.log("=".repeat(52));
        const rpiMult = 7;
        console.log(`  Full prove  : ~${(mean(fullTimes) * rpiMult / 1000).toFixed(1)} s   (offline, once per AST)`);
        console.log(`  Witness gen : ~${(mean(witnessOnlyTimes) * rpiMult).toFixed(0)} ms  (online proxy per BSM)`);
    }
    console.log("\nRun  npm run bench-batch  for batch verification numbers.");
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
