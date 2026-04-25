/**
 * bench_raba_ablation.js — RABA Design-Choice Ablation
 *
 * Empirically validates two design choices claimed in the paper:
 *
 *   (1) Adaptive-k vs Fixed-k batch sizing
 *       Fixed-k  : always dispatch min(|Q|, k_max) proofs per sub-batch
 *       Adaptive-k: dispatch min(|Q|, floor(Δ/T1)) where Δ = time to earliest
 *                  deadline in the queue — reduces batch size when deadline is tight
 *       Claim: adaptive-k reduces deadline misses for proofs arriving late in window.
 *
 *   (2) Per-class DCV vs Global DCV
 *       Per-class  : DCV fallback scoped to the class batch that failed (paper design)
 *       Global DCV : DCV applied to a merged batch of all three priority classes
 *       Claim: per-class DCV prevents one class's adversarial injection from delaying
 *              the other two; global DCV lets Routine-class injection stall Emergency.
 *
 * Scenario: Dense+Adversarial (k=50, w=1 corrupted Routine proof per window).
 * Four configurations tested: {fixed-k, adaptive-k} × {per-class DCV, global DCV}.
 *
 * Prerequisites:
 *   node benchmark/bench_dcv.js    (warms proof cache at results/dcv_proofs.json)
 *
 * Run: node benchmark/bench_raba_ablation.js
 */

"use strict";

const snarkjs = require("snarkjs");
const { batchVerify, buildBatchCurve } = require("./groth16_batch_verify");
const fs   = require("fs");
const path = require("path");
const os   = require("os");

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
const WASM        = path.join("build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY        = path.join("keys",  "ulp_v2v_auth_final.zkey");
const VK          = path.join("keys",  "verification_key.json");
const IN          = path.join("build", "input.json");
const PROOF_CACHE = path.join("results", "dcv_proofs.json");

// ---------------------------------------------------------------------------
// RABA parameters (must match bench_raba.js)
// ---------------------------------------------------------------------------
const T_WINDOW_MS = 100;
const T1          = 38;
const D_E         = 200;
const D_W         = 500;
const D_R         = 2000;
const K_E_MAX     = Math.floor(D_E / T1);              // 5
const K_W_MAX     = Math.floor(D_W / T1);              // 13
const K_R_MAX     = Math.min(50, Math.floor(D_R / T1)); // 50

const P_E = 0.05;
const P_W = 0.25;

const N_WINDOWS  = 300;
const POOL_MIN   = 60;
const K_SCENARIO = 50;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
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

const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
const pct  = (arr, p) => {
    const s = [...arr].sort((a, b) => a - b);
    return s[Math.floor(p / 100 * s.length)] ?? s[s.length - 1];
};

function corruptProof(proof) {
    const c = JSON.parse(JSON.stringify(proof));
    c.pi_a[0] = (BigInt(c.pi_a[0]) + BigInt(1)).toString();
    return c;
}

async function dcv(proofs, pubs, vk, curve, counter) {
    const k = proofs.length;
    counter.calls++;
    if (k === 1) {
        await batchVerify(proofs, pubs, vk, curve);
        return;
    }
    const mid  = Math.floor(k / 2);
    const lRes = await batchVerify(proofs.slice(0, mid), pubs.slice(0, mid), vk, curve);
    const rRes = await batchVerify(proofs.slice(mid),    pubs.slice(mid),    vk, curve);
    counter.calls++;
    if (!lRes.valid) await dcv(proofs.slice(0, mid), pubs.slice(0, mid), vk, curve, counter);
    if (!rRes.valid) await dcv(proofs.slice(mid),    pubs.slice(mid),    vk, curve, counter);
}

async function loadPool(minSize, baseInput) {
    if (fs.existsSync(PROOF_CACHE)) {
        try {
            const cached = JSON.parse(fs.readFileSync(PROOF_CACHE));
            if (Array.isArray(cached.proofs) && cached.proofs.length >= minSize) {
                console.log(`  Loaded ${cached.proofs.length} proofs from cache.`);
                return cached.proofs;
            }
        } catch { /* fall through */ }
    }
    console.log(`  Generating ${minSize} proofs (run bench_dcv.js first to speed this up)...`);
    const pool = [];
    for (let i = 0; i < minSize; i++) {
        const inp = { ...baseInput, pkOt: (BigInt(baseInput.pkOt) + BigInt(i + 1)).toString() };
        process.stdout.write(`  Proof ${i + 1}/${minSize}  \r`);
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(inp, WASM, ZKEY);
        pool.push({ proof, publicSignals });
    }
    fs.mkdirSync("results", { recursive: true });
    fs.writeFileSync(PROOF_CACHE, JSON.stringify({ k: minSize, proofs: pool }, null, 2));
    console.log(`  Generated ${minSize} proofs.`);
    return pool;
}

// ---------------------------------------------------------------------------
// adaptiveBatchSize: compute k for next dispatch given remaining queue
//   queue   : array of entries with .sim arrival time
//   D_class : deadline offset (ms)
//   kMax    : hard ceiling
//   wallStart: performance.now() at window start
// ---------------------------------------------------------------------------
function adaptiveBatchSize(queue, i, D_class, kMax, wallStart) {
    const now  = performance.now() - wallStart;
    const dMin = Math.min(...queue.slice(i).map(e => e.sim + D_class));
    const delta = Math.max(0, dMin - now);
    return Math.min(queue.length - i, Math.max(1, Math.floor(delta / T1)));
}

// ---------------------------------------------------------------------------
// Per-class DCV window
// ---------------------------------------------------------------------------
async function runWindowPerClass(pool, vk, curve, k, adaptiveK) {
    const n_E = Math.max(1, Math.round(P_E * k));
    const n_W = Math.round(P_W * k);

    const arrivals = Array.from({ length: k }, (_, idx) => ({
        sim: Math.random() * T_WINDOW_MS,
        pi:  idx % pool.length,
    })).sort((a, b) => a.sim - b.sim);

    const Eq = arrivals.slice(0, n_E).map(a => ({
        ...a, cls: "E", proof: pool[a.pi].proof, pub: pool[a.pi].publicSignals,
    }));
    const Wq = arrivals.slice(n_E, n_E + n_W).map(a => ({
        ...a, cls: "W", proof: pool[a.pi].proof, pub: pool[a.pi].publicSignals,
    }));
    const Rq = arrivals.slice(n_E + n_W).map(a => ({
        ...a, cls: "R", proof: pool[a.pi].proof, pub: pool[a.pi].publicSignals,
    }));

    // Inject one corrupted proof into Routine batch
    if (Rq.length > 1) {
        const badPos = Math.floor(Math.random() * Rq.length);
        Rq[badPos] = { ...Rq[badPos], proof: corruptProof(Rq[badPos].proof) };
    }

    const results   = [];
    const wallStart = performance.now();

    // Emergency: individual verify (k_E* = 5, always fits in D_E=200ms)
    for (const e of Eq) {
        await snarkjs.groth16.verify(vk, e.pub, e.proof);
        const wallMs = performance.now() - wallStart;
        results.push({ cls: "E", wallMs, deadline: e.sim + D_E,
            met: wallMs <= e.sim + D_E, margin: e.sim + D_E - wallMs });
    }

    // Warning: batched
    for (let i = 0; i < Wq.length; ) {
        const kd = adaptiveK
            ? adaptiveBatchSize(Wq, i, D_W, K_W_MAX, wallStart)
            : Math.min(Wq.length - i, K_W_MAX);
        const sub = Wq.slice(i, i + kd);
        await batchVerify(sub.map(e => e.proof), sub.map(e => e.pub), vk, curve);
        const wallMs = performance.now() - wallStart;
        for (const e of sub)
            results.push({ cls: "W", wallMs, deadline: e.sim + D_W,
                met: wallMs <= e.sim + D_W, margin: e.sim + D_W - wallMs });
        i += kd;
    }

    // Routine: batched, DCV on failure
    for (let i = 0; i < Rq.length; ) {
        const kd = adaptiveK
            ? adaptiveBatchSize(Rq, i, D_R, K_R_MAX, wallStart)
            : Math.min(Rq.length - i, K_R_MAX);
        const sub    = Rq.slice(i, i + kd);
        const proofs = sub.map(e => e.proof);
        const pubs   = sub.map(e => e.pub);
        const init   = await batchVerify(proofs, pubs, vk, curve);
        if (!init.valid) {
            const counter = { calls: 0 };
            await dcv(proofs, pubs, vk, curve, counter);
        }
        const wallMs = performance.now() - wallStart;
        for (const e of sub)
            results.push({ cls: "R", wallMs, deadline: e.sim + D_R,
                met: wallMs <= e.sim + D_R, margin: e.sim + D_R - wallMs });
        i += kd;
    }

    return results;
}

// ---------------------------------------------------------------------------
// Global DCV window: merge all three queues into one batch, DCV on failure
// ---------------------------------------------------------------------------
async function runWindowGlobalDCV(pool, vk, curve, k, adaptiveK) {
    const n_E = Math.max(1, Math.round(P_E * k));
    const n_W = Math.round(P_W * k);

    const arrivals = Array.from({ length: k }, (_, idx) => ({
        sim: Math.random() * T_WINDOW_MS,
        pi:  idx % pool.length,
    })).sort((a, b) => a.sim - b.sim);

    const classOf = (idx) => idx < n_E ? "E" : idx < n_E + n_W ? "W" : "R";
    const deadlineOf = (cls, sim) =>
        cls === "E" ? sim + D_E : cls === "W" ? sim + D_W : sim + D_R;

    // Build all entries with class-specific deadlines
    const all = arrivals.map((a, idx) => {
        const cls = classOf(idx);
        return { ...a, cls, proof: pool[a.pi].proof, pub: pool[a.pi].publicSignals,
                 deadline: deadlineOf(cls, a.sim) };
    });

    // Inject one corrupted proof at a random Routine position
    const routineIdx = all.map((e, i) => e.cls === "R" ? i : -1).filter(i => i >= 0);
    if (routineIdx.length > 1) {
        const badPos = routineIdx[Math.floor(Math.random() * routineIdx.length)];
        all[badPos] = { ...all[badPos], proof: corruptProof(all[badPos].proof) };
    }

    const results   = [];
    const wallStart = performance.now();

    // Sort by deadline (EDF across all classes)
    const queue = [...all].sort((a, b) => a.deadline - b.deadline);

    // Dispatch in batches — size governed by tightest remaining deadline
    for (let i = 0; i < queue.length; ) {
        let kd;
        if (adaptiveK) {
            const now   = performance.now() - wallStart;
            const dMin  = Math.min(...queue.slice(i).map(e => e.deadline));
            const delta = Math.max(0, dMin - now);
            kd = Math.min(queue.length - i, Math.max(1, Math.floor(delta / T1)));
        } else {
            // Fixed global k: use tightest class k_max in the remaining queue
            const clsSet = new Set(queue.slice(i).map(e => e.cls));
            kd = clsSet.has("E") ? K_E_MAX : clsSet.has("W") ? K_W_MAX : K_R_MAX;
            kd = Math.min(queue.length - i, kd);
        }

        const sub    = queue.slice(i, i + kd);
        const proofs = sub.map(e => e.proof);
        const pubs   = sub.map(e => e.pub);
        const init   = await batchVerify(proofs, pubs, vk, curve);
        if (!init.valid) {
            const counter = { calls: 0 };
            await dcv(proofs, pubs, vk, curve, counter);
        }
        const wallMs = performance.now() - wallStart;
        for (const e of sub)
            results.push({ cls: e.cls, wallMs, deadline: e.deadline,
                met: wallMs <= e.deadline, margin: e.deadline - wallMs });
        i += kd;
    }

    return results;
}

// ---------------------------------------------------------------------------
// Aggregate per-class stats across all windows
// ---------------------------------------------------------------------------
function aggregate(cls, windowResults) {
    const rows = windowResults.flat().filter(r => r.cls === cls);
    if (!rows.length) return null;
    const met = rows.filter(r => r.met).length;
    return {
        n:          rows.length,
        hitPct:     (met / rows.length * 100).toFixed(1),
        meanWall:   mean(rows.map(r => r.wallMs)).toFixed(1),
        p99Wall:    pct(rows.map(r => r.wallMs), 99).toFixed(1),
        minMargin:  Math.min(...rows.map(r => r.margin)).toFixed(1),
    };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
    const hw = detectHardware();
    console.log("\n" + "=".repeat(72));
    console.log("  ULP-V2V-Auth — RABA Design-Choice Ablation");
    console.log("  {Fixed-k, Adaptive-k} × {Per-class DCV, Global DCV}");
    console.log(`  Scenario : Dense+Adv k=${K_SCENARIO} w=1  |  N_WINDOWS=${N_WINDOWS}`);
    console.log(`  Hardware : ${hw}`);
    console.log("=".repeat(72));

    for (const f of [WASM, ZKEY, VK, IN]) {
        if (!fs.existsSync(f)) { console.error(`Missing: ${f} — run npm run setup`); process.exit(1); }
    }

    const baseInput  = JSON.parse(fs.readFileSync(IN));
    const vk         = JSON.parse(fs.readFileSync(VK));
    const batchCurve = await buildBatchCurve();
    const pool       = await loadPool(POOL_MIN, baseInput);

    const CONFIGS = [
        { label: "Fixed-k    + Per-class DCV  [paper design]", adaptiveK: false, dcvMode: "per-class" },
        { label: "Adaptive-k + Per-class DCV",                  adaptiveK: true,  dcvMode: "per-class" },
        { label: "Fixed-k    + Global DCV",                     adaptiveK: false, dcvMode: "global"    },
        { label: "Adaptive-k + Global DCV",                     adaptiveK: true,  dcvMode: "global"    },
    ];

    const allResults = [];

    for (const cfg of CONFIGS) {
        console.log(`\n${"─".repeat(72)}`);
        console.log(`[Config] ${cfg.label}`);
        console.log(`${"─".repeat(72)}`);

        const windowResults = [];
        const printEvery = Math.max(1, Math.floor(N_WINDOWS / 10));

        for (let w = 0; w < N_WINDOWS; w++) {
            const res = cfg.dcvMode === "per-class"
                ? await runWindowPerClass(pool, vk, batchCurve, K_SCENARIO, cfg.adaptiveK)
                : await runWindowGlobalDCV(pool, vk, batchCurve, K_SCENARIO, cfg.adaptiveK);
            windowResults.push(res);
            if ((w + 1) % printEvery === 0 || w === N_WINDOWS - 1)
                process.stdout.write(`  [${w + 1}/${N_WINDOWS}]  \r`);
        }
        console.log("");

        const E = aggregate("E", windowResults);
        const W = aggregate("W", windowResults);
        const R = aggregate("R", windowResults);

        for (const [cls, agg, D] of [["E", E, D_E], ["W", W, D_W], ["R", R, D_R]]) {
            if (!agg) continue;
            const ok = parseFloat(agg.minMargin) >= 0;
            console.log(
                `  Class ${cls} (D=${D}ms): hit=${agg.hitPct}%  P99=${agg.p99Wall}ms  ` +
                `min-margin=${agg.minMargin}ms  ${ok ? "✓ ALL MET" : "✗ MISS"}`
            );
        }

        allResults.push({
            config: cfg.label, adaptiveK: cfg.adaptiveK, dcvMode: cfg.dcvMode,
            Emergency: E, Warning: W, Routine: R,
        });
    }

    // ---------------------------------------------------------------------------
    // Summary table
    // ---------------------------------------------------------------------------
    console.log("\n" + "=".repeat(72));
    console.log("  Ablation Summary — Dense+Adv (k=50, w=1)");
    console.log("=".repeat(72));
    console.log(
        `  ${"Configuration".padEnd(44)} ` +
        `${"E-hit".padStart(6)} ${"W-hit".padStart(6)} ${"R-hit".padStart(6)}`
    );
    console.log("  " + "─".repeat(66));
    for (const r of allResults) {
        const E = r.Emergency ? r.Emergency.hitPct + "%" : "n/a";
        const W = r.Warning   ? r.Warning.hitPct   + "%" : "n/a";
        const R = r.Routine   ? r.Routine.hitPct   + "%" : "n/a";
        console.log(
            `  ${r.config.padEnd(44)} ` +
            `${E.padStart(6)} ${W.padStart(6)} ${R.padStart(6)}`
        );
    }
    console.log(`\n  Expected: Per-class DCV isolates injection to Routine class (E/W unaffected).`);
    console.log(`            Global DCV stalls all classes until the Routine DCV completes.`);
    console.log(`            Adaptive-k marginally improves late-arrival compliance vs fixed-k.`);

    // Save
    fs.mkdirSync("results", { recursive: true });
    const outPath = path.join("results", "bench_raba_ablation.json");
    fs.writeFileSync(outPath, JSON.stringify({
        benchmark:   "raba_ablation",
        description: "Adaptive-k vs Fixed-k × Per-class DCV vs Global DCV",
        hardware:    hw,
        scenario:    `Dense+Adv k=${K_SCENARIO} w=1`,
        N_windows:   N_WINDOWS,
        T1_ms:       T1,
        timestamp:   new Date().toISOString(),
        configs:     allResults,
    }, null, 2));
    console.log(`\nResults saved → ${outPath}`);
    await batchCurve.terminate();
}

main().catch(err => { console.error(err); process.exit(1); });
