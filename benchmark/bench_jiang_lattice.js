/**
 * bench_jiang_lattice.js
 *
 * Benchmarks the sender-side authentication cost of Jiang & Guo's
 * anonymous authentication scheme as described in:
 *
 *   Jiang & Guo, "An Anonymous Authentication Scheme for V2V Communication
 *   Based on Zero-Knowledge Proof and Blockchain," IEEE IoT-J, 2025.  [Ref 14]
 *
 * Original hardware: Intel i5-6500 @ 3.2 GHz, 16 GB RAM, Windows, Python.
 * This script runs the equivalent operations on the current machine.
 *
 * Lattice-ZKP sender authentication cost (paper Table III / Eq. 14):
 *
 *   T_auth = T_r + T_h + 5·T_m + 4·T_s
 *
 * Where (measured on i5-6500 in original paper):
 *   T_r = 0.0185 ms  — sample r from discrete Gaussian D_{n,σ}  (n = 2048 draws)
 *   T_h = 0.0495 ms  — compute challenge hash  c ∈ {0,1}^256
 *   T_m = 1.4060 ms  — matrix-vector mult: A · z,  A ∈ Z_q^{m×n}, m=n=2048, q=257
 *   T_s = 0.0151 ms  — scalar vector ops (n additions mod q)
 *   Total (paper i5-6500) ≈ 7.258 ms
 *
 * The dominant term is T_m: five 2048×2048 matrix-vector multiplications mod 257.
 * We measure each component independently and derive T_auth for fair HW comparison.
 *
 * Run:  node benchmark/bench_jiang_lattice.js
 */

const crypto = require("crypto");
const os     = require("os");
const fs     = require("fs");
const path   = require("path");

const N_WARMUP = 3;
const N_RUNS   = 20;

// Lattice parameters from Jiang & Guo
const M = 2048;    // matrix rows (= n in paper notation)
const N = 2048;    // matrix cols / vector length
const Q = 257;     // prime modulus
const SIGMA = 3.2; // discrete Gaussian std dev (typical for n=2048 ISIS)

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

// Generate random m×n matrix with entries uniform in [0, q-1]
function randomMatrix(m, n, q) {
    const A = new Int32Array(m * n);
    for (let i = 0; i < m * n; i++) {
        A[i] = (Math.random() * q) | 0;
    }
    return A;
}

// Generate random n-vector with entries uniform in [0, q-1]
function randomVector(n, q) {
    const v = new Int32Array(n);
    for (let i = 0; i < n; i++) {
        v[i] = (Math.random() * q) | 0;
    }
    return v;
}

// Matrix-vector multiplication: result[i] = Σ_j A[i,j] * z[j]  mod q
// A: Int32Array of shape (m, n) stored row-major
// z: Int32Array of length n
function matVecMul(A, z, m, n, q) {
    const result = new Int32Array(m);
    for (let i = 0; i < m; i++) {
        let sum = 0;
        const rowOff = i * n;
        for (let j = 0; j < n; j++) {
            sum += A[rowOff + j] * z[j];
        }
        // Reduce mod q (sum can be up to n * (q-1)^2 ≈ 2048 * 256^2 ≈ 134M — safe in float64)
        result[i] = ((sum % q) + q) % q;
    }
    return result;
}

// Discrete Gaussian sampling: draw n samples from D_{Z,σ} via Box-Muller
function sampleDiscreteGaussian(n, sigma) {
    const out = new Int32Array(n);
    for (let i = 0; i < n; i += 2) {
        const u1 = 1 - Math.random();
        const u2 = Math.random();
        const mag = sigma * Math.sqrt(-2 * Math.log(u1));
        out[i]     = Math.round(mag * Math.cos(2 * Math.PI * u2));
        if (i + 1 < n) out[i + 1] = Math.round(mag * Math.sin(2 * Math.PI * u2));
    }
    return out;
}

// Scalar vector operations: component-wise (a + b) mod q
function scalarVecOps(a, b, n, q) {
    const c = new Int32Array(n);
    for (let j = 0; j < n; j++) {
        c[j] = (a[j] + b[j]) % q;
    }
    return c;
}

async function main() {
    const hw = detectHardware();
    console.log("=".repeat(64));
    console.log("  Jiang & Guo Lattice-ZKP Auth Benchmark");
    console.log(`  Hardware   : ${hw}`);
    console.log(`  Lattice    : m=n=${M}, q=${Q} (ISIS problem)`);
    console.log(`  Warmup     : ${N_WARMUP}  |  Measured : ${N_RUNS}`);
    console.log("=".repeat(64));

    // Pre-generate public matrix A (system parameter, not part of auth cost)
    process.stdout.write(`\n  Generating public matrix A (${M}×${N}, q=${Q})... `);
    const A = randomMatrix(M, N, Q);
    console.log("done.\n");

    // -------------------------------------------------------
    // [T_m] Matrix-vector multiplication: A · z  mod 257
    // This is the dominant cost — performed 5× per authentication
    // -------------------------------------------------------
    console.log("[T_m] Matrix-vector mult A·z mod 257 (2048×2048)...");
    const tm_times = [];
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const z = randomVector(N, Q);
        const t0 = performance.now();
        matVecMul(A, z, M, N, Q);
        const elapsed = performance.now() - t0;
        if (i < N_WARMUP) {
            process.stdout.write(`  warm-up ${i + 1}/${N_WARMUP}: ${elapsed.toFixed(1)} ms\r`);
        } else {
            tm_times.push(elapsed);
            process.stdout.write(`  run ${i - N_WARMUP + 1}/${N_RUNS}: ${elapsed.toFixed(1)} ms   \r`);
        }
    }
    console.log("");
    const tm_mean = mean(tm_times);
    const tm_std  = std(tm_times);
    console.log(`  T_m mean : ${tm_mean.toFixed(3)} ms   std : ${tm_std.toFixed(3)} ms`);
    console.log(`  (paper, i5-6500): 1.406 ms`);

    // -------------------------------------------------------
    // [T_r] Discrete Gaussian sampling: draw n=2048 samples
    // -------------------------------------------------------
    console.log("\n[T_r] Discrete Gaussian sampling (n=2048, σ=3.2)...");
    const tr_times = [];
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const t0 = performance.now();
        sampleDiscreteGaussian(N, SIGMA);
        const elapsed = performance.now() - t0;
        if (i >= N_WARMUP) tr_times.push(elapsed);
    }
    const tr_mean = mean(tr_times);
    const tr_std  = std(tr_times);
    console.log(`  T_r mean : ${tr_mean.toFixed(4)} ms   std : ${tr_std.toFixed(4)} ms`);
    console.log(`  (paper, i5-6500): 0.0185 ms`);

    // -------------------------------------------------------
    // [T_h] Challenge hash: SHA-256 over concatenated public inputs
    // -------------------------------------------------------
    console.log("\n[T_h] SHA-256 hash (challenge c ∈ {0,1}^256)...");
    const th_times = [];
    // Simulate input: commitment vector A·y (2048 ints) as bytes
    const hashInput = Buffer.alloc(M * 4);
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const t0 = performance.now();
        crypto.createHash("sha256").update(hashInput).digest();
        const elapsed = performance.now() - t0;
        if (i >= N_WARMUP) th_times.push(elapsed);
    }
    const th_mean = mean(th_times);
    const th_std  = std(th_times);
    console.log(`  T_h mean : ${th_mean.toFixed(4)} ms   std : ${th_std.toFixed(4)} ms`);
    console.log(`  (paper, i5-6500): 0.0495 ms`);

    // -------------------------------------------------------
    // [T_s] Scalar vector operations: component-wise add mod q
    // -------------------------------------------------------
    console.log("\n[T_s] Scalar vector ops (n=2048 additions mod 257)...");
    const ts_times = [];
    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const a = randomVector(N, Q);
        const b = randomVector(N, Q);
        const t0 = performance.now();
        scalarVecOps(a, b, N, Q);
        const elapsed = performance.now() - t0;
        if (i >= N_WARMUP) ts_times.push(elapsed);
    }
    const ts_mean = mean(ts_times);
    const ts_std  = std(ts_times);
    console.log(`  T_s mean : ${ts_mean.toFixed(4)} ms   std : ${ts_std.toFixed(4)} ms`);
    console.log(`  (paper, i5-6500): 0.0151 ms`);

    // -------------------------------------------------------
    // Total authentication cost: T_auth = T_r + T_h + 5·T_m + 4·T_s
    // -------------------------------------------------------
    const total_this = tr_mean + th_mean + 5 * tm_mean + 4 * ts_mean;
    const total_paper = 0.0185 + 0.0495 + 5 * 1.406 + 4 * 0.0151;  // 7.258 ms

    console.log("\n" + "=".repeat(64));
    console.log("  Jiang & Guo Lattice-ZKP Auth — T_auth Summary");
    console.log("=".repeat(64));
    console.log(`\n  T_auth = T_r + T_h + 5·T_m + 4·T_s\n`);
    console.log(`  ${"Component".padEnd(30)} ${"This machine".padStart(13)} ${"Paper (i5-6500)".padStart(16)}`);
    console.log(`  ${"-".repeat(59)}`);
    console.log(`  ${"T_r  (Gaussian, n=2048)".padEnd(30)} ${(tr_mean.toFixed(4) + " ms").padStart(13)} ${"0.0185 ms".padStart(16)}`);
    console.log(`  ${"T_h  (SHA-256 hash)".padEnd(30)} ${(th_mean.toFixed(4) + " ms").padStart(13)} ${"0.0495 ms".padStart(16)}`);
    console.log(`  ${"T_m  (2048×2048 matmul)".padEnd(30)} ${(tm_mean.toFixed(3) + " ms").padStart(13)} ${"1.4060 ms".padStart(16)}`);
    console.log(`  ${"T_s  (scalar vec ops)".padEnd(30)} ${(ts_mean.toFixed(4) + " ms").padStart(13)} ${"0.0151 ms".padStart(16)}`);
    console.log(`  ${"-".repeat(59)}`);
    console.log(`  ${"T_auth (total)".padEnd(30)} ${(total_this.toFixed(3) + " ms").padStart(13)} ${(total_paper.toFixed(3) + " ms").padStart(16)}`);
    console.log(`\n  SNAP online cost      : 0.439 ms`);
    console.log(`  SNAP speedup vs this  : ${(total_this / 0.439).toFixed(1)}× faster`);

    const results = {
        benchmark          : "jiang_guo_lattice_auth",
        reference          : "Jiang & Guo, IEEE IoT-J 2025 — Anonymous Auth ZKP + Blockchain V2V",
        description        : "T_auth = T_r + T_h + 5*T_m + 4*T_s; T_m = 2048×2048 matmul mod 257",
        hardware           : hw,
        lattice_params     : { m: M, n: N, q: Q, sigma: SIGMA },
        n_warmup           : N_WARMUP,
        n_runs             : N_RUNS,
        timestamp          : new Date().toISOString(),
        T_r_mean_ms        : parseFloat(tr_mean.toFixed(4)),
        T_r_std_ms         : parseFloat(tr_std.toFixed(4)),
        T_h_mean_ms        : parseFloat(th_mean.toFixed(4)),
        T_h_std_ms         : parseFloat(th_std.toFixed(4)),
        T_m_mean_ms        : parseFloat(tm_mean.toFixed(3)),
        T_m_std_ms         : parseFloat(tm_std.toFixed(3)),
        T_m_times_ms       : tm_times.map(t => parseFloat(t.toFixed(3))),
        T_s_mean_ms        : parseFloat(ts_mean.toFixed(4)),
        T_s_std_ms         : parseFloat(ts_std.toFixed(4)),
        T_auth_total_ms    : parseFloat(total_this.toFixed(3)),
        original_hw        : "Intel i5-6500 @ 3.2 GHz, 16 GB RAM, Windows, Python",
        original_T_auth_ms : parseFloat(total_paper.toFixed(3)),
        snap_online_ms     : 0.439,
        speedup_vs_snap    : parseFloat((total_this / 0.439).toFixed(2)),
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_jiang_lattice.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\n  Results saved → ${outPath}`);
}

main().catch(err => { console.error(err); process.exit(1); });
