/**
 * bench_wu_clss.js
 *
 * Benchmarks the sender-side signing cost of Wu et al.'s certificateless
 * signature scheme (CLSS) on BN254, as described in:
 *
 *   Wu et al., "Certificateless Signature Scheme With Batch Verification
 *   for V2I Communication in VANETs," IEEE TDSC, 2025.  [Ref 25]
 *
 * Original hardware: Intel i7-4790 @ 3.6 GHz (Ubuntu, MIRACL library).
 * This script runs the equivalent BN254 G1 operations on the current machine.
 *
 * CLSS sign per message (from paper Section III-B, Algorithm 1):
 *   (1)  r_i  ← Z_q                               (random scalar)
 *   (2)  R_i  = r_i · P                            (1× G1 scalar mult)
 *   (3)  h_i  = H(M_i ‖ R_i ‖ PK_i)               (hash — negligible)
 *   (4)  V_i  = u_i·sv_i·ψ(W) + u_i·d_i + r_i·(ψ(W) + P₀)
 *            = (u_i·sv_i + r_i)·ψ(W) + u_i·d_i + r_i·P₀
 *                                                   (3× G1 scalar mult + 2× G1 add)
 *
 * Total per-sign: 4 G1 scalar multiplications + 2 G1 additions on BN254.
 * Uses ffjavascript (same WASM BN254 backend as snarkjs and our SNAP circuit).
 *
 * Run:  node benchmark/bench_wu_clss.js
 */

const { buildBn128 } = require("ffjavascript");
const os   = require("os");
const fs   = require("fs");
const path = require("path");

const N_WARMUP = 3;
const N_RUNS   = 20;

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

async function main() {
    const hw = detectHardware();
    console.log("=".repeat(64));
    console.log("  Wu et al. CLSS Sign Benchmark — BN254 G1");
    console.log(`  Hardware   : ${hw}`);
    console.log(`  Warmup     : ${N_WARMUP}  |  Measured : ${N_RUNS}`);
    console.log("=".repeat(64));
    console.log("\nBuilding BN128/BN254 WASM module (ffjavascript)...");

    const bn128 = await buildBn128();
    const { G1, Fr } = bn128;

    // --- Key setup: one-time pre-computation, NOT measured ---
    //
    // ψ(W) : G2→G1 image of the WKM accumulator point
    //         (Type-2 bilinear map sends G2→G1; modelled here as random G1 point)
    // d_pt : vehicle partial private-key component (G1 point from KGC)
    // P₀   : system parameter (G1 point, published in system params)
    const G     = G1.g;
    const psiW  = G1.timesScalar(G, Fr.random());
    const d_pt  = G1.timesScalar(G, Fr.random());
    const P0    = G1.timesScalar(G, Fr.random());

    // Per-vehicle key scalars (generated once at registration, constant per session)
    const u   = Fr.random();               // partial private key scalar (from KGC)
    const sv  = Fr.random();               // secret value (from KGC)
    const usv = Fr.mul(u, sv);             // u·sv — pre-computed once per session

    console.log("  Key material ready.\n");

    // -------------------------------------------------------
    // Benchmark: per-message CLSS signing
    // Measured operations: 4× G1 scalar mult + 2× G1 add
    // -------------------------------------------------------
    const times = [];

    for (let i = 0; i < N_WARMUP + N_RUNS; i++) {
        const t0 = performance.now();

        // Step 1: random nonce r_i ← Z_q
        const r = Fr.random();

        // Step 2: R_i = r_i · P  [1× scalar mult]
        const R = G1.timesScalar(G, r);

        // Step 4: V_i = (u_i·sv_i + r_i)·ψ(W) + u_i·d_i + r_i·P₀
        //            [3× scalar mult + 2× G1 add]
        const coeff1 = Fr.add(usv, r);
        const V1 = G1.timesScalar(psiW, coeff1);   // (u·sv + r)·ψ(W)
        const V2 = G1.timesScalar(d_pt, u);          // u · d
        const V3 = G1.timesScalar(P0,   r);           // r · P₀
        const _V  = G1.add(G1.add(V1, V2), V3);       // sum (result discarded but forces eval)

        const elapsed = performance.now() - t0;

        if (i < N_WARMUP) {
            process.stdout.write(`  warm-up ${i + 1}/${N_WARMUP}: ${elapsed.toFixed(1)} ms\r`);
        } else {
            times.push(elapsed);
            process.stdout.write(`  run ${i - N_WARMUP + 1}/${N_RUNS}: ${elapsed.toFixed(1)} ms   \r`);
        }
    }
    console.log("");

    const m_ms  = mean(times);
    const sd_ms = std(times);

    console.log("\n" + "=".repeat(64));
    console.log("  Wu et al. CLSS Sign — Results");
    console.log("=".repeat(64));
    console.log(`\n  Per-sign operations  : 4× G1 scalar mult + 2× G1 add (BN254)`);
    console.log(`  Sign time (mean)     : ${m_ms.toFixed(3)} ms`);
    console.log(`  Sign time (std)      : ${sd_ms.toFixed(3)} ms`);
    console.log(`\n  Original paper value : ~11.0 ms (i7-4790 @ 3.6 GHz, MIRACL, Ubuntu)`);
    console.log(`  This machine         : ${m_ms.toFixed(3)} ms (${hw})`);
    console.log(`\n  SNAP online cost     : 0.439 ms`);
    if (m_ms > 0) {
        console.log(`  SNAP speedup vs Wu   : ${(m_ms / 0.439).toFixed(1)}× (on this hardware)`);
    }

    const results = {
        benchmark         : "wu_clss_sign",
        reference         : "Wu et al., IEEE TDSC 2025 — Certificateless Signature w/ Batch Verification",
        description       : "Per-message sender sign: 4x G1 scalar mult + 2x G1 add on BN254",
        hardware          : hw,
        library           : "ffjavascript (snarkjs WASM BN254 backend)",
        n_warmup          : N_WARMUP,
        n_runs            : N_RUNS,
        timestamp         : new Date().toISOString(),
        sign_mean_ms      : parseFloat(m_ms.toFixed(3)),
        sign_std_ms       : parseFloat(sd_ms.toFixed(3)),
        sign_times_ms     : times.map(t => parseFloat(t.toFixed(3))),
        original_hw       : "Intel i7-4790 @ 3.6 GHz, Ubuntu, MIRACL library",
        original_sign_ms  : 11.0,
        snap_online_ms    : 0.439,
        speedup_vs_snap   : parseFloat((m_ms / 0.439).toFixed(2)),
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_wu_clss.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\n  Results saved → ${outPath}`);

    await bn128.terminate();
}

main().catch(err => { console.error(err); process.exit(1); });
