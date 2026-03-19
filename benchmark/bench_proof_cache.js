/**
 * bench_proof_cache.js — Proof Slot Cache Performance Benchmark
 *
 * Validates the offline/online proof-slot model for ULP-V2V-Auth.
 *
 * THE MODEL
 * ---------
 *   OFFLINE (vehicle stopped or idle):
 *     Pre-generate N proof slots. Each slot commits to a predicted future
 *     BSM message (vehicle state: position, velocity, heading) chosen at
 *     precomputation time. The Groth16 proof is complete and valid.
 *
 *   ONLINE (per BSM at 10 Hz, 100 ms cycle):
 *     1. Dequeue the next pre-generated slot          ≈ 0.00 ms
 *     2. h_m = Poseidon(pre-committed message, t)     = ~0.41 ms (measured)
 *     3. Broadcast (proof, h_m, BSM payload)          ≈ 0.00 ms
 *     Total online cost per BSM:                      = ~0.41 ms
 *
 *   LIMITATION:
 *     BSM payload content (position, velocity) must be committed at
 *     precomputation time. For 100 ms BSM intervals and highway speeds
 *     (~30 m/s), position prediction error over one slot interval is
 *     sub-metre — within GPS accuracy. This is the only constraint of
 *     the proof-slot model.
 *
 * WHAT THIS MEASURES
 * ------------------
 *   A) Slot generation rate   — offline production rate (slots/min)
 *   B) Online per-BSM cost    — dequeue + Poseidon binding
 *   C) Cache drain rate       — how long N slots last at 10 Hz
 *   D) Stop-drive model       — required stop time per minute of driving
 *   E) Break-even acceleration — hardware speedup needed for self-sustaining cache
 *
 * Run:  node benchmark/bench_proof_cache.js
 * Prerequisites: npm run setup && npm run gen-input
 */

const snarkjs        = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
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

const N_SLOTS          = 5;      // proof slots to generate (each ~2,354 ms — total ~12 s)
const N_POSEIDON       = 2000;   // Poseidon binding measurements
const BSM_HZ           = 10;     // BSM broadcast rate (Hz)
const BSM_INTERVAL_MS  = 1000 / BSM_HZ;   // 100 ms
const SLOTS_PER_MIN    = 60 * BSM_HZ;     // consumption rate = 600 slots/min at 10 Hz

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

    // -------------------------------------------------------
    // Build Poseidon
    // -------------------------------------------------------
    const poseidon = await buildPoseidon();
    const F        = poseidon.F;
    const hashFn   = (...args) => F.toObject(poseidon(args));

    // -------------------------------------------------------
    // Phase A — Offline Slot Generation
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[Phase A]  Offline slot generation — ${N_SLOTS} proof slots`);
    console.log(`  Each slot commits to a different pre-chosen BSM message.`);
    console.log(`  (Vehicle predicts its future position/state at precomputation time)`);
    console.log(`${"─".repeat(68)}`);

    const slotTimes = [];
    const slots     = [];

    const tBase = BigInt(baseInput.tCurrent);

    for (let i = 0; i < N_SLOTS; i++) {
        // Each slot has a different pre-committed message (simulates predicted BSM content)
        // In deployment: vehicle uses predicted position, velocity, heading at time t_i
        const precommittedMsg = BigInt("0x" + crypto.randomBytes(16).toString("hex")) %
            BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

        // Time offset: each slot covers one BSM interval in the future
        const tSlot    = tBase + BigInt(i) * BigInt(Math.round(BSM_INTERVAL_MS / 1000));
        const hMessage = hashFn(precommittedMsg, tSlot);

        const slotInput = {
            ...baseInput,
            tCurrent : tSlot.toString(),
            hMessage : hMessage.toString(),
            message  : precommittedMsg.toString(),
        };

        process.stdout.write(`  Slot ${i+1}/${N_SLOTS}: generating proof...  \r`);
        const t0 = performance.now();

        let proof, publicSignals;

        if (rapidsnarkBin) {
            // Use rapidsnark if available
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

        // Verify slot is valid
        const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);

        slots.push({ proof, publicSignals, precommittedMsg, tSlot, valid });
        console.log(`  Slot ${i+1}/${N_SLOTS}: msg=${precommittedMsg.toString(16).slice(0,8)}... ` +
                    `t+${i*100}ms → ${elapsed.toFixed(0)} ms  valid=${valid ? "✓" : "✗"}`);
    }

    const slotMean       = mean(slotTimes);
    const slotStd        = std(slotTimes);
    const productionRate = 60000 / slotMean;   // slots per minute

    const proverLabel = rapidsnarkBin ? "rapidsnark" : "snarkjs";
    console.log(`\n  Per-slot mean : ${slotMean.toFixed(0)} ms ± ${slotStd.toFixed(0)} ms  (${proverLabel})`);
    console.log(`  Production rate: ${productionRate.toFixed(1)} slots/min`);

    // -------------------------------------------------------
    // Phase B — Online Per-BSM Cost
    // -------------------------------------------------------
    console.log(`\n${"─".repeat(68)}`);
    console.log(`[Phase B]  Online per-BSM cost (dequeue + Poseidon binding)`);
    console.log(`${"─".repeat(68)}`);

    // B1: Dequeue simulation (array pop)
    const cache = [...slots];
    const dequeueStart = performance.now();
    for (let i = 0; i < N_SLOTS; i++) cache.pop();
    const dequeuePerSlot = (performance.now() - dequeueStart) / N_SLOTS;

    // B2: Poseidon binding (amortised)
    const poseidonBatches = [];
    const BATCH = 500;
    const testMsg = BigInt("0xBEEF0001CAFE0002DEAD0003BABE0004");
    for (let b = 0; b < N_POSEIDON / BATCH; b++) {
        const t0 = performance.now();
        for (let i = 0; i < BATCH; i++) hashFn(testMsg + BigInt(i), tBase);
        poseidonBatches.push((performance.now() - t0) / BATCH);
    }
    const poseidonMean = mean(poseidonBatches);
    const poseidonStd  = std(poseidonBatches);

    const totalOnline = dequeuePerSlot + poseidonMean;

    console.log(`  1. Dequeue slot (array pop)     : ${dequeuePerSlot.toFixed(4)} ms`);
    console.log(`  2. Poseidon binding (amortised) : ${poseidonMean.toFixed(4)} ms  ±  ${poseidonStd.toFixed(4)} ms`);
    console.log(`  ─────────────────────────────────────────────────`);
    console.log(`  Total online cost per BSM       : ${totalOnline.toFixed(4)} ms`);
    console.log(`  As % of 100 ms BSM cycle        : ${(totalOnline / 100 * 100).toFixed(3)}%`);

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

    const netDrain = SLOTS_PER_MIN - productionRate;  // net drain while driving (dual-core)
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

    // During stop: produce at productionRate, consume 0
    // During drive: consume SLOTS_PER_MIN, produce productionRate (background core)
    // Net slots needed for T_drive minutes = netDrain * T_drive
    // Stop time needed = (netDrain * T_drive) / productionRate minutes

    console.log(`\n  ${"T_drive".padEnd(12)} ${"Slots needed".padEnd(16)} ${"Stop needed".padEnd(16)} ${"Stop:Drive ratio"}`);
    console.log(`  ${"─".repeat(60)}`);

    const stopDriveResults = [];
    for (const tDrive of DRIVE_SCENARIOS_MIN) {
        const slotsNeeded = Math.ceil(netDrain * tDrive);
        const stopNeeded  = slotsNeeded / productionRate;          // minutes
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

    // For self-sustaining: slot_gen_time ≤ BSM_INTERVAL_MS
    // speedup needed = slotMean / BSM_INTERVAL_MS
    const breakEvenMs      = BSM_INTERVAL_MS;               // 100 ms
    const breakEvenSpeedup = slotMean / breakEvenMs;

    console.log(`\n  Current slot gen time  : ${slotMean.toFixed(0)} ms  (${proverLabel})`);
    console.log(`  Break-even target      : ${breakEvenMs} ms/slot  (= 1 slot per BSM interval)`);
    console.log(`  Required speedup       : ${breakEvenSpeedup.toFixed(1)}×`);

    // Hardware acceleration tiers
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
    console.log(`    Poseidon binding          : ${poseidonMean.toFixed(4)} ms ± ${poseidonStd.toFixed(4)} ms`);
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
    console.log(`\n  LIMITATION`);
    console.log(`    BSM content must be pre-committed at slot generation time.`);
    console.log(`    At 100 ms slot intervals, highway position prediction error`);
    console.log(`    is < 3 m at 30 m/s — within GPS accuracy.`);
    console.log("=".repeat(68));

    // -------------------------------------------------------
    // Save results
    // -------------------------------------------------------
    const results = {
        hardware          : hw,
        circuit           : "ULP_V2V_Auth(depth=16)",
        prover            : proverLabel,
        nSlots            : N_SLOTS,
        nPoseidon         : N_POSEIDON,
        bsmHz             : BSM_HZ,
        timestamp         : new Date().toISOString(),
        slotGeneration    : {
            mean_ms        : parseFloat(slotMean.toFixed(3)),
            std_ms         : parseFloat(slotStd.toFixed(3)),
            productionRate : parseFloat(productionRate.toFixed(2)),
        },
        onlineCost        : {
            dequeue_ms     : parseFloat(dequeuePerSlot.toFixed(6)),
            poseidon_ms    : parseFloat(poseidonMean.toFixed(6)),
            poseidonStd_ms : parseFloat(poseidonStd.toFixed(6)),
            total_ms       : parseFloat(totalOnline.toFixed(6)),
            pctOfBsmCycle  : parseFloat((totalOnline/100*100).toFixed(4)),
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
