/**
 * Benchmark 4: BN254 Primitive Operation Microbenchmark
 *
 * Measures individual BN254 curve primitive operation costs on this hardware,
 * then projects Wu et al. (zhang2024) CLSS scheme costs using their published
 * operation-count formulas (Table II of their paper).
 *
 * Wu et al. formulas:
 *   Sign(M_i):          T_H + 2*T_G1 + T_G2
 *   Verify(1 msg):      3*T_b + 2*T_G1 + T_H + 3*T_s1
 *   BatchVerify(n msg): 3*T_b + 2n*T_G1 + n*T_H + 3n*T_s1
 *
 * Jiang & Guo (jiang2024) are handled analytically — their scheme requires
 * RSU+BS+blockchain consensus and cannot execute on OBU-class hardware.
 *
 * Run on RPi 4:  node benchmark/bench_primitives.js
 */

"use strict";

const { buildBn128 } = require("ffjavascript");
const { createHash }  = require("crypto");
const { performance } = require("perf_hooks");

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

function sha256(data) {
  return createHash("sha256").update(data).digest();
}

/**
 * Runs `fn` warmup times (discarded), then `runs` measured times.
 * Returns { mean, std } in ms.
 */
async function bench(name, fn, warmup = 3, runs = 20) {
  for (let i = 0; i < warmup; i++) await fn();

  const times = [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    await fn();
    times.push(performance.now() - t0);
  }

  const mean = times.reduce((a, b) => a + b, 0) / runs;
  const variance = times.map(t => (t - mean) ** 2).reduce((a, b) => a + b, 0) / runs;
  const std  = Math.sqrt(variance);

  console.log(`  ${name.padEnd(42)} ${mean.toFixed(3).padStart(8)} ± ${std.toFixed(3).padStart(7)} ms  (${runs} runs)`);
  return { mean, std };
}

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */

async function main() {
  console.log("=".repeat(72));
  console.log("  Benchmark 4: BN254 Primitive Microbenchmark + Wu et al. Projection");
  console.log("=".repeat(72));
  console.log("  Platform:", process.platform, process.arch);
  console.log("  Node.js: ", process.version);
  console.log();

  /* ---- Build curve ---- */
  const curve = await buildBn128(true);   // singleThread=true, matches other benchmarks
  const { G1, G2, Fr } = curve;

  /* Fixed inputs (reused across all runs for fairness) */
  const scalarFull  = Fr.random();                                      // 254-bit scalar
  const scalar60    = BigInt("0x" + sha256("se-test-seed-60b").toString("hex").slice(0, 15)); // ~60-bit small exp
  const G1gen       = G1.g;
  const G2gen       = G2.g;
  const G1genAff    = G1.toAffine(G1gen);
  const G2genAff    = G2.toAffine(G2gen);
  // A second distinct G1 point for pairing (G1gen * 2)
  const G1p2        = G1.add(G1gen, G1gen);
  const G1p2Aff     = G1.toAffine(G1p2);

  console.log("--- BN254 Primitive Operations ---");

  /* T_G1: full 254-bit scalar multiplication in G1 */
  const { mean: T_G1 } = await bench("T_G1  G1 scalar mult (254-bit)",
    () => { G1.timesScalar(G1gen, scalarFull); });

  /* T_G2: full 254-bit scalar multiplication in G2 */
  const { mean: T_G2 } = await bench("T_G2  G2 scalar mult (254-bit)",
    () => { G2.timesScalar(G2gen, scalarFull); });

  /* T_s1: 60-bit small-exponent G1 multiplication (small-exponent batch test) */
  const { mean: T_s1 } = await bench("T_s1  G1 scalar mult (60-bit, SE test)",
    () => { G1.timesScalar(G1gen, scalar60); });

  /* T_b: BN254 ate pairing — cross-check against earlier measurement */
  const { mean: T_b } = await bench("T_b   BN254 full pairing",
    async () => { await curve.pairing(G1genAff, G2genAff); });

  /* T_H: hash-to-G1 approximation.
   * Wu et al.'s H_1: {0,1}* -> G1 uses try-and-increment (hash + sqrt + conditional).
   * Conservative approximation: SHA256 field hash + 1 G1 scalar mult.
   * T_H is therefore bounded above by ~T_G1 + negligible hash cost.
   */
  const msgBuf = Buffer.alloc(128, 0xab);
  const { mean: T_hash_sha256 } = await bench("T_hash SHA256 (128 B input)",
    () => { sha256(msgBuf); }, 10, 1000);

  // T_H = hash-to-field (negligible) + map-to-curve (≈ T_G1 scalar mult)
  const T_H = T_G1 + T_hash_sha256;

  console.log();
  console.log("--- Derived ---");
  console.log(`  T_H  hash-to-G1 (T_G1 + SHA256)               ${T_H.toFixed(3).padStart(8)} ms  (conservative upper bound)`);
  console.log(`  T_b  (earlier direct measurement, 20 runs)     ${"22.510".padStart(8)} ms  (cross-check)`);
  console.log();

  /* ---------------------------------------------------------------- */
  /*  Wu et al. (zhang2024) — Projected cost on THIS hardware          */
  /* ---------------------------------------------------------------- */

  console.log("=".repeat(72));
  console.log("  Wu et al. (zhang2024) — CLSS+BatchVerify Cost Projection");
  console.log("  Formula source: Wu et al. Table II (IEEE TDSC, 2025)");
  console.log("=".repeat(72));

  const sign_wu = T_H + 2 * T_G1 + T_G2;
  console.log(`\n  Sign (per BSM, run every 100 ms):  ${sign_wu.toFixed(1)} ms`);
  console.log(`    = T_H(${T_H.toFixed(1)}) + 2*T_G1(${(2*T_G1).toFixed(1)}) + T_G2(${T_G2.toFixed(1)})`);

  console.log("\n  Batch Verification (n messages):");
  console.log(`  ${"n".padStart(3)}  ${"BatchVerify (ms)".padStart(18)}  ${"Sequential (ms)".padStart(18)}  ${"Speedup".padStart(9)}`);
  console.log("  " + "-".repeat(52));

  for (const n of [1, 5, 10, 20, 30, 50]) {
    const batch = 3 * T_b + 2 * n * T_G1 + n * T_H + 3 * n * T_s1;
    const seq   = n * (3 * T_b + 2 * T_G1 + T_H + 3 * T_s1);
    const spdup = seq / batch;
    console.log(`  ${String(n).padStart(3)}  ${batch.toFixed(1).padStart(18)}  ${seq.toFixed(1).padStart(18)}  ${spdup.toFixed(2).padStart(9)}x`);
  }

  /* ---------------------------------------------------------------- */
  /*  Jiang & Guo (jiang2024) — Analytical projection                  */
  /* ---------------------------------------------------------------- */

  console.log();
  console.log("=".repeat(72));
  console.log("  Jiang & Guo (jiang2024) — Analytical Projection");
  console.log("  Source: their Table III (Intel i5-6500 @ 3.5 GHz, Python)");
  console.log("=".repeat(72));

  // Their primitive times (ms) on Intel i5-6500 @ 3.5 GHz, Python
  const T_r_i5  = 0.0185;    // random number gen
  const T_h_i5  = 0.0495;    // hash operation
  const T_m_i5  = 1.406;     // matrix-vector multiplication
  const T_s_i5  = 0.0151;    // scalar-vector multiplication

  // Approximate CPU speed ratio: Cortex-A72 @ 1.8 GHz vs i5-6500 @ 3.5 GHz
  // Python on ARM is also ~1.5-2x slower than on x86 for NumPy matrix ops
  const cpuRatio = (3.5 / 1.8) * 1.5;   // ≈ 2.92x total penalty

  const T_m_rpi  = T_m_i5  * cpuRatio;
  const T_h_rpi  = T_hash_sha256;         // measured directly above
  const T_r_rpi  = T_hash_sha256 * 0.4;  // random gen ≈ similar to short hash
  const T_s_rpi  = 0.01 * cpuRatio;       // scalar-vector very fast

  const vehicle_zkp_i5  = T_r_i5 + 3*T_h_i5  + 5*T_m_i5  + 4*T_s_i5;   // 7.26 ms (matches paper)
  const vehicle_zkp_rpi = T_r_rpi + 3*T_h_rpi + 5*T_m_rpi + 4*T_s_rpi;

  console.log(`\n  Vehicle ZKP computation:`);
  console.log(`    On i5-6500 (reported by paper):  ${vehicle_zkp_i5.toFixed(2)} ms`);
  console.log(`    Projected on Cortex-A72 (RPi4):  ${vehicle_zkp_rpi.toFixed(1)} ms  (~${cpuRatio.toFixed(1)}x slowdown)`);
  console.log(`\n  Note: Jiang & Guo verification runs on Base Stations (BS), NOT on vehicles.`);
  console.log(`  TRUG-PBFT consensus latency (from their Fig 7): 200–800 ms (additional).`);
  console.log(`  => Total auth latency on RPi4 OBU: ${(vehicle_zkp_rpi + 200).toFixed(0)}–${(vehicle_zkp_rpi + 800).toFixed(0)} ms.`);
  console.log(`  => INCOMPATIBLE with 100 ms V2V BSM cycle. Infrastructure required.`);

  /* ---------------------------------------------------------------- */
  /*  Final comparison summary                                          */
  /* ---------------------------------------------------------------- */

  console.log();
  console.log("=".repeat(72));
  console.log("  Summary: Sender Cost Comparison on RPi 4 OBU-Class Hardware");
  console.log("=".repeat(72));
  console.log(`  SCMS/ECDSA sign (measured):        0.199 ms  (traditional baseline)`);
  console.log(`  Wu et al. sign (projected):        ${sign_wu.toFixed(1).padStart(5)} ms  (per BSM — runs every 100 ms)`);
  console.log(`  ULP-V2V-Auth online (measured):    0.439 ms  (Poseidon-2 hash only)`);
  console.log(`  Jiang & Guo ZKP gen (projected):   ${vehicle_zkp_rpi.toFixed(1).padStart(5)} ms  (+ 200–800 ms consensus)`);
  console.log();
  console.log("  Receiver Batch k=30 Comparison:");
  const wu_batch30 = 3 * T_b + 2 * 30 * T_G1 + 30 * T_H + 3 * 30 * T_s1;
  console.log(`  SCMS/ECDSA batch k=30 (measured):  12.08 ms  (sequential ECDSA verify)`);
  console.log(`  Wu et al. batch k=30 (projected):  ${wu_batch30.toFixed(1).padStart(5)} ms  (3 pairings + 60 G1 mults)`);
  console.log(`  ULP-V2V-Auth batch k=30 (measured): 400.0 ms  (33 pairings, full ZKP unlinkability)`);
  console.log(`  Jiang & Guo k=30 (projected):      N/A   (BS+RSU+consensus, not V2V-capable)`);
  console.log();
  console.log("  Key trade-off: ULP-V2V-Auth pays higher receiver batch cost to achieve");
  console.log("  full cryptographic unlinkability — property not provided by SCMS or Wu et al.");
  console.log();

  await curve.terminate();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
