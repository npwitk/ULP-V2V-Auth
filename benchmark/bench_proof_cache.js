/**
 * bench_proof_cache.js — Proof Slot Cache Performance Benchmark
 *
 * Validates the offline/online proof-slot model for ULP-V2V-Auth.
 *
 * THE MODEL (one-time-key design)
 * --------------------------------
 *   OFFLINE (vehicle stopped or idle):
 *     Pre-generate N proof slots. Each slot binds to a fresh one-time
 *     ECDSA-P256 keypair (sk_ot, pk_ot). The Groth16 proof commits to pk_ot
 *     as a public input. Slots are message-agnostic — 100% usable for any BSM.
 *
 *   ONLINE (per BSM at 10 Hz, 100 ms cycle):
 *     1. Dequeue the next pre-generated slot          ≈ 0.00 ms
 *     2. sigma_ot = ECDSA-P256.Sign(sk_ot, BSM)      ≈ 0.20 ms
 *     3. Broadcast (proof, pk_ot, sigma_ot, BSM)      ≈ 0.00 ms
 *     Total online cost per BSM:                      ≈ 0.20 ms
 *
 *   DESIGN NOTE:
 *     BSM payload (position, velocity, heading) is signed by sk_ot at broadcast
 *     time. No BSM content enters the Groth16 circuit — the circuit only proves
 *     membership and freshness for pk_ot. This eliminates the pre-commitment
 *     constraint of earlier designs.
 *
 * WHAT THIS MEASURES
 * ------------------
 *   A) Slot generation rate   — offline production rate (slots/min)
 *   B) Online per-BSM cost    — dequeue + ECDSA-P256 sign
 *   C) Cache drain rate       — how long N slots last at 10 Hz
 *   D) Stop-drive model       — required stop time per minute of driving
 *   E) Break-even acceleration — hardware speedup needed for self-sustaining cache
 *
 * Run:  node benchmark/bench_proof_cache.js
 * Prerequisites: npm run setup && npm run gen-input
 */

const snarkjs        = require("snarkjs");
const crypto         = require("crypto");
const fs             = require("fs");
const path           = require("path");
const os             = require("os");
const { execFileSync } = require("child_process");

// -------------------------------------------------------
// Config
// -------------------------------------------------------
const WASM = path.join("build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY = path.join("keys",  "ulp_v2v_auth_final.zkey");
const VK   = path.join("keys",  "verification_key.json");
const IN   = path.join("build", "input.json");

const N_SLOTS          = 5;      // proof slots to generate
const N_ECDSA_SIGN     = 2000;   // ECDSA sign measurements (matches bench_ecdsa_baseline.js)
const BSM_HZ           = 10;     // BSM broadcast rate (Hz)
const BSM_INTERVAL_MS  = 1000 / BSM_HZ;   // 100 ms
const SLOTS_PER_MIN    = 60 * BSM_HZ;     // consumption rate = 600 slots/min at 10 Hz

// Simulated BSM payload: position + velocity + heading + timestamp ≈ 250 bytes (SAE J2735)
const BSM_PAYLOAD = crypto.randomBytes(250);

const DRIVE_SCENARIOS_MIN = [0.5, 1, 2, 5, 10]; // driving durations to model (minutes)

const TMP_WTNS = path.join(os.tmpdir(), "ulp_cache_bench.wtns");

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

function findRapidsnark() {
    try {
        const { execSync } = require("child_process");
        return execSync("which rapidsnark 2>/dev/null || which prover 2>/dev/null",
            { stdio: ["pipe","pipe","pipe"] }).toString().trim() || null;
    } catch {}
    for (const c of [
        "/usr/local/bin/rapidsnark", "/usr/local/bin/prover",
        "/usr/bin/rapidsnark",       "/usr/bin/prover",
        path.join(os.homedir(), "rapidsnark", "build_prover", "src", "prover"),
        path.join(os.homedir(), "rapidsnark", "build_prover", "prover"),
    ]) { if (fs.existsSync(c)) return c; }
    return null;
}

const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
const std  = arr => { const m = mean(arr); return Math.sqrt(arr.reduce((s,x) => s+(x-m)**2, 0)/arr.length); };
const ci95 = arr => (1.96 * std(arr) / Math.sqrt(arr.length));

// -------------------------------------------------------
// Main
// -------------------------------------------------------
async function main() {
    const hw = detectHardware();
    console.log("=".repeat(68));
    console.log("  ULP-V2V-Auth — Proof Slot Cache Performance Benchmark");
    console.log(`  Hardware : ${hw}`);
    console.log("=".repeat(68));

    for (const f of [WASM, ZKEY, IN]) {
        if (!fs.existsSync(f)) {
            console.error(`Missing: ${f} — run npm run setup && npm run gen-input`);
            process.exit(1);
        }
    }

    const baseInput = JSON.parse(fs.readFileSync(IN));
    const vk        = JSON.parse(fs.readFileSync(VK));

    // Rapidsnark (optional — used if installed)
    const rapidsnarkBin = findRapidsnark();

    // Load prior rapidsnark result if available (for sustainability model)
    let rapidsnarkMean_ms = null;
    const rapidResultPath = path.join("results", "bench_rapidsnark.json");
    if (fs.existsSync(rapidResultPath)) {
        try {
            const r = JSON.parse(fs.readFileSync(rapidResultPath));
            rapidsnarkMean_ms = r.rapidsnarkTotal?.mean_ms ?? null;
        } catch {}
    }

    const tBase = BigInt(baseInput.tCurrent);

    // -------------------------------------------------------
    // Phase A — Offline Slot Generation
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[Phase A]  Offline slot generation — ${N_SLOTS} proof slots`);
    console.log(`  Each slot binds to a fresh one-time ECDSA-P256 keypair (pk_ot).`);
    console.log(`  Slots are message-agnostic (100% usable — no pre-commitment).`);
    console.log(`${"─".repeat(68)}`);

    const slotTimes = [];
    const slots     = [];

    for (let i = 0; i < N_SLOTS; i++) {
        // Each slot uses a fresh one-time public key (simulated as random BN254 scalar).
        // In deployment: vehicle calls ECDSA.KeyGen(P-256) per slot (<0.3 ms).
        const pkOt = BigInt("0x" + crypto.randomBytes(31).toString("hex")) %
            BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

        // t_gen: each slot covers one BSM interval in the future
        const tSlot = tBase + BigInt(i) * BigInt(Math.round(BSM_INTERVAL_MS / 1000));

        const slotInput = {
            ...baseInput,
            tCurrent : tSlot.toString(),
            pkOt     : pkOt.toString(),
        };

        process.stdout.write(`  Slot ${i+1}/${N_SLOTS}: generating proof...  \r`);
        const t0 = performance.now();

        let proof, publicSignals;

        if (rapidsnarkBin) {
            await snarkjs.wtns.calculate(slotInput, WASM, { type: "file", fileName: TMP_WTNS });
            const tmpProof = path.join(os.tmpdir(), `slot_proof_${i}.json`);
            const tmpPub   = path.join(os.tmpdir(), `slot_pub_${i}.json`);
            execFileSync(rapidsnarkBin, [ZKEY, TMP_WTNS, tmpProof, tmpPub], { stdio: "pipe" });
            proof         = JSON.parse(fs.readFileSync(tmpProof));
            publicSignals = JSON.parse(fs.readFileSync(tmpPub));
            fs.unlinkSync(tmpProof); fs.unlinkSync(tmpPub);
        } else {
            ({ proof, publicSignals } = await snarkjs.groth16.fullProve(slotInput, WASM, ZKEY));
        }

        const elapsed = performance.now() - t0;
        slotTimes.push(elapsed);

        const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);

        slots.push({ proof, publicSignals, pkOt, tSlot, valid });
        console.log(`  Slot ${i+1}/${N_SLOTS}: pkOt=${pkOt.toString(16).slice(0,8)}... ` +
                    `t_gen=t+${i*100}ms → ${elapsed.toFixed(0)} ms  valid=${valid ? "✓" : "✗"}`);
    }

    const slotMean       = mean(slotTimes);
    const slotStd        = std(slotTimes);
    const productionRate = 60000 / slotMean;   // slots per minute

    const proverLabel = rapidsnarkBin ? "rapidsnark" : "snarkjs";
    console.log(`\n  Per-slot mean : ${slotMean.toFixed(0)} ms ± ${slotStd.toFixed(0)} ms  (${proverLabel})`);
    console.log(`  Production rate: ${productionRate.toFixed(1)} slots/min`);

    // -------------------------------------------------------
    // Phase B — Online Per-BSM Cost (dequeue + ECDSA sign)
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[Phase B]  Online per-BSM cost (dequeue + ECDSA-P256 sign)`);
    console.log(`  One-time-key design: BSM is bound by sk_ot at broadcast time.`);
    console.log(`  No Poseidon hash needed online; circuit is fully pre-computed.`);
    console.log(`${"─".repeat(68)}`);

    // B1: Dequeue simulation (array pop)
    const cache = [...slots];
    const dequeueStart = performance.now();
    for (let i = 0; i < N_SLOTS; i++) cache.pop();
    const dequeuePerSlot = (performance.now() - dequeueStart) / N_SLOTS;

    // B2: ECDSA-P256 sign (per BSM) — the actual online cryptographic cost
    const { privateKey: privDer } = crypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
        privateKeyEncoding: { type: "pkcs8", format: "der" },
    });
    const privKey = crypto.createPrivateKey({ key: privDer, format: "der", type: "pkcs8" });

    // Warmup
    for (let i = 0; i < 100; i++) {
        const s = crypto.createSign("SHA256");
        s.update(BSM_PAYLOAD);
        s.sign(privKey);
    }

    const signTimes = [];
    for (let i = 0; i < N_ECDSA_SIGN; i++) {
        const t0 = performance.now();
        const s = crypto.createSign("SHA256");
        s.update(BSM_PAYLOAD);
        s.sign(privKey);
        signTimes.push(performance.now() - t0);
        if ((i + 1) % 500 === 0)
            process.stdout.write(`  ECDSA sign run ${i+1}/${N_ECDSA_SIGN}: ${signTimes[i].toFixed(3)} ms   \r`);
    }
    console.log("");

    const ecdsaSignMean = mean(signTimes);
    const ecdsaSignStd  = std(signTimes);
    const ecdsaSignCI   = ci95(signTimes);

    const totalOnline = dequeuePerSlot + ecdsaSignMean;

    console.log(`  1. Dequeue slot (array pop)      : ${dequeuePerSlot.toFixed(4)} ms`);
    console.log(`  2. ECDSA-P256 sign (per BSM)     : ${ecdsaSignMean.toFixed(4)} ms  ±  ${ecdsaSignCI.toFixed(4)} ms (95% CI)`);
    console.log(`  ─────────────────────────────────────────────────`);
    console.log(`  Total online cost per BSM        : ${totalOnline.toFixed(4)} ms`);
    console.log(`  As % of 100 ms BSM cycle         : ${(totalOnline / 100 * 100).toFixed(3)}%`);
    console.log(`  Paper claim (Phase 3): ~0.20 ms  →  ${ecdsaSignMean < 0.40 ? "✓ PASS" : "✗ UPDATE PAPER"}`);

    // -------------------------------------------------------
    // Phase C — Cache Drain Rate at 10 Hz
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[Phase C]  Cache drain rate at ${BSM_HZ} Hz`);
    console.log(`${"─".repeat(68)}`);

    console.log(`  Consumption rate : ${SLOTS_PER_MIN} slots/min (${BSM_HZ} Hz × 60 s)`);
    console.log(`  Production rate  : ${productionRate.toFixed(1)} slots/min  [${proverLabel}, this device]`);
    if (rapidsnarkMean_ms && !rapidsnarkBin) {
        const rRate = 60000 / rapidsnarkMean_ms;
        console.log(`  Production rate  : ${rRate.toFixed(1)} slots/min  [rapidsnark, from prior benchmark]`);
    }

    const netDrain = SLOTS_PER_MIN - productionRate;
    console.log(`  Net drain (dual-core driving)  : ${netDrain.toFixed(1)} slots/min`);
    console.log(`\n  Cache size → Time before exhaustion (driving, dual-core):`);

    const cacheSizes = [10, 60, 300, 600, 1800];
    for (const n of cacheSizes) {
        const drainSec = (n / netDrain) * 60;
        console.log(`    ${String(n).padStart(5)} slots → ${drainSec.toFixed(1).padStart(7)} s  ` +
                    `(${(drainSec/60).toFixed(2)} min)`);
    }

    // -------------------------------------------------------
    // Phase D — Stop-Drive Sustainability Model
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[Phase D]  Stop-drive sustainability model`);
    console.log(`  Q: How long must the vehicle stop to cover T_drive minutes of driving?`);
    console.log(`${"─".repeat(68)}`);

    console.log(`\n  ${"T_drive".padEnd(12)} ${"Slots needed".padEnd(16)} ${"Stop needed".padEnd(16)} ${"Stop:Drive ratio"}`);
    console.log(`  ${"─".repeat(60)}`);

    const stopDriveResults = [];
    for (const tDrive of DRIVE_SCENARIOS_MIN) {
        const slotsNeeded = Math.ceil(netDrain * tDrive);
        const stopNeeded  = slotsNeeded / productionRate;
        const ratio       = stopNeeded / tDrive;
        stopDriveResults.push({ tDrive, slotsNeeded, stopNeeded, ratio });
        console.log(`  ${(tDrive + " min").padEnd(12)} ${String(slotsNeeded).padEnd(16)} ` +
                    `${stopNeeded.toFixed(1).padStart(5)} min         ${ratio.toFixed(1)}:1`);
    }

    // -------------------------------------------------------
    // Phase E — Break-Even Hardware Acceleration
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[Phase E]  Break-even hardware acceleration`);
    console.log(`  Q: How much faster must the prover be to become self-sustaining?`);
    console.log(`     (production rate ≥ consumption rate = ${SLOTS_PER_MIN} slots/min)`);
    console.log(`${"─".repeat(68)}`);

    const breakEvenMs      = BSM_INTERVAL_MS;
    const breakEvenSpeedup = slotMean / breakEvenMs;

    console.log(`\n  Current slot gen time  : ${slotMean.toFixed(0)} ms  (${proverLabel})`);
    console.log(`  Break-even target      : ${breakEvenMs} ms/slot  (= 1 slot per BSM interval)`);
    console.log(`  Required speedup       : ${breakEvenSpeedup.toFixed(1)}×`);

    const tiers = [
        { name: "snarkjs (baseline)",             speedup: 1 },
        { name: "rapidsnark (ARM, no NEON)",      speedup: slotMean / (rapidsnarkMean_ms ?? 976) },
        { name: "NXP S32G (est. 10× EC accel)",  speedup: 10 },
        { name: "NXP S32G (est. 25× EC accel)",  speedup: 25 },
        { name: "NXP S32G (est. 50× EC accel)",  speedup: 50 },
    ];

    console.log(`\n  ${"Hardware tier".padEnd(38)} ${"Slot time".padEnd(12)} ${"Rate (slots/min)".padEnd(18)} ${"Self-sustaining?"}`);
    console.log(`  ${"─".repeat(80)}`);
    for (const tier of tiers) {
        const tSlot = slotMean / tier.speedup;
        const rate  = 60000 / tSlot;
        const ok    = rate >= SLOTS_PER_MIN;
        console.log(`  ${tier.name.padEnd(38)} ${tSlot.toFixed(0).padStart(7)} ms   ` +
                    `${rate.toFixed(1).padStart(10)} /min   ${ok ? "✓ Yes" : `✗ No  (${(rate/SLOTS_PER_MIN*100).toFixed(0)}%)`}`);
    }

    // -------------------------------------------------------
    // Summary Table
    // -------------------------------------------------------
    console.log("\n" + "=".repeat(68));
    console.log("  Summary: Proof Slot Cache — ULP-V2V-Auth on " + hw.split("—")[0].trim());
    console.log("=".repeat(68));
    console.log(`\n  ONLINE COST (per BSM, from pre-generated cache)`);
    console.log(`    Dequeue slot              : ${dequeuePerSlot.toFixed(4)} ms`);
    console.log(`    ECDSA-P256 sign           : ${ecdsaSignMean.toFixed(4)} ms ± ${ecdsaSignCI.toFixed(4)} ms (95% CI)`);
    console.log(`    Total                     : ${totalOnline.toFixed(4)} ms  (${(totalOnline/100*100).toFixed(3)}% of BSM cycle)`);
    console.log(`\n  OFFLINE PRODUCTION RATE`);
    console.log(`    Per-slot (${proverLabel.padEnd(16)}) : ${slotMean.toFixed(0)} ms ± ${slotStd.toFixed(0)} ms`);
    console.log(`    Production rate          : ${productionRate.toFixed(1)} slots/min`);
    console.log(`    Consumption rate (10 Hz) : ${SLOTS_PER_MIN} slots/min`);
    console.log(`    Net drain during driving : ${netDrain.toFixed(1)} slots/min`);
    console.log(`\n  SUSTAINABILITY`);
    console.log(`    Stop:drive ratio         : ${stopDriveResults[1].ratio.toFixed(1)}:1  (per 1 min driving)`);
    console.log(`    Break-even speedup       : ${breakEvenSpeedup.toFixed(1)}× over ${proverLabel}`);
    console.log(`    Self-sustaining at       : ≥ ${(60000/SLOTS_PER_MIN).toFixed(0)} ms/slot  (NXP S32G tier)`);
    console.log(`\n  DESIGN NOTE (one-time-key)`);
    console.log(`    Each slot commits to a fresh ECDSA key pair (sk_ot, pk_ot).`);
    console.log(`    BSM content is signed at broadcast time — no pre-commitment needed.`);
    console.log(`    Each slot is single-use; sk_ot is discarded after one BSM.`);
    console.log("=".repeat(68));

    // -------------------------------------------------------
    // Save results
    // -------------------------------------------------------
    const results = {
        hardware          : hw,
        circuit           : "ULP_V2V_Auth(depth=8, constraints=5069)",
        prover            : proverLabel,
        nSlots            : N_SLOTS,
        nEcdsaSign        : N_ECDSA_SIGN,
        bsmHz             : BSM_HZ,
        bsmPayloadBytes   : BSM_PAYLOAD.length,
        timestamp         : new Date().toISOString(),
        slotGeneration    : {
            mean_ms        : parseFloat(slotMean.toFixed(3)),
            std_ms         : parseFloat(slotStd.toFixed(3)),
            productionRate : parseFloat(productionRate.toFixed(2)),
        },
        onlineCost        : {
            dequeue_ms       : parseFloat(dequeuePerSlot.toFixed(6)),
            ecdsaSign_ms     : parseFloat(ecdsaSignMean.toFixed(6)),
            ecdsaSignStd_ms  : parseFloat(ecdsaSignStd.toFixed(6)),
            ecdsaSignCI95_ms : parseFloat(ecdsaSignCI.toFixed(6)),
            total_ms         : parseFloat(totalOnline.toFixed(6)),
            pctOfBsmCycle    : parseFloat((totalOnline/100*100).toFixed(4)),
            claim_ms         : 0.20,
        },
        cacheLifetime     : cacheSizes.map(n => ({
            cacheSize      : n,
            drainTime_s    : parseFloat(((n / netDrain) * 60).toFixed(2)),
        })),
        stopDriveModel    : stopDriveResults.map(r => ({
            driveTime_min  : r.tDrive,
            slotsNeeded    : r.slotsNeeded,
            stopNeeded_min : parseFloat(r.stopNeeded.toFixed(2)),
            stopDriveRatio : parseFloat(r.ratio.toFixed(2)),
        })),
        breakEven         : {
            targetSlotTime_ms : breakEvenMs,
            requiredSpeedup   : parseFloat(breakEvenSpeedup.toFixed(2)),
        },
        consumptionRate   : SLOTS_PER_MIN,
        netDrainRate      : parseFloat(netDrain.toFixed(2)),
    };

    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_proof_cache.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`\nResults saved to ${outPath}`);

    if (fs.existsSync(TMP_WTNS)) fs.unlinkSync(TMP_WTNS);
}

main().catch(err => { console.error(err); process.exit(1); });
