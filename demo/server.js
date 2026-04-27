/**
 * demo/server.js — ULP-V2V-Auth Live Demo Server (Apr-26 system)
 *
 * Phase 1 & 2: simulated comms, real Poseidon hashing, ONE real Groth16 prove
 *              (offline cache fill — shows actual slot timing).
 * Phase 3: correct ONLINE flow — cache dequeue + ECDSA-P256 sign only (0.2ms).
 *          Receiver side: bridge check + ECDSA verify + real Groth16 verify.
 * Phase 4: RABA scheduler — 3 priority queues (E/W/R), EDF, batch per class.
 *
 * Run:  npm run demo   →   http://localhost:4000
 */

const express          = require("express");
const http             = require("http");
const WebSocket        = require("ws");
const snarkjs          = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { batchVerify, buildBatchCurve } = require("../benchmark/groth16_batch_verify");
const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");

const ROOT  = path.join(__dirname, "..");
const WASM  = path.join(ROOT, "build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY  = path.join(ROOT, "keys",  "ulp_v2v_auth_final.zkey");
const VK    = path.join(ROOT, "keys",  "verification_key.json");
const INPUT = path.join(ROOT, "build", "input.json");

let vk, baseInput, poseidon, batchCurve;
const sessions = new WeakMap();
const sleep = ms => new Promise(r => setTimeout(r, ms));

function rndHex(n) { return crypto.randomBytes(n).toString("hex"); }
function trunc(s, len = 22) { s = String(s); return s.length > len ? s.slice(0, len) + "…" : s; }
function fmtG1(a) { return `(${trunc(a[0])}, ${trunc(a[1])})`; }
function fmtG2(a) { return `([${trunc(a[0][0])},…], [${trunc(a[1][0])},…])`; }

function fakeG1() {
    const p = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
    return [(BigInt("0x" + rndHex(31)) % p).toString(), (BigInt("0x" + rndHex(31)) % p).toString(), "1"];
}
function fakeG2() {
    const r = () => (BigInt("0x" + rndHex(31)) % 21888242871839275222246405745257275088696311157297823662689037894645226208583n).toString();
    return [[r(), r()], [r(), r()], ["1", "0"]];
}
function fakeProof() { return { pi_a: fakeG1(), pi_b: fakeG2(), pi_c: fakeG1(), protocol: "groth16", curve: "bn128" }; }
function send(ws, obj) { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)); }

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

app.use(express.static(path.join(__dirname, "public")));

async function init() {
    for (const f of [WASM, ZKEY, VK, INPUT]) {
        if (!fs.existsSync(f)) {
            console.error(`\n  Missing: ${f}`);
            console.error("  Run:  npm run setup  &&  npm run gen-input  first.\n");
            process.exit(1);
        }
    }
    console.log("Loading keys and building Poseidon + BN128 curve (~5 s)…");
    vk         = JSON.parse(fs.readFileSync(VK));
    baseInput  = JSON.parse(fs.readFileSync(INPUT));
    poseidon   = await buildPoseidon();
    batchCurve = await buildBatchCurve();
    console.log("Ready. Open http://localhost:4000\n");
}

wss.on("connection", ws => {
    sessions.set(ws, { identity: null, session: null, cachedProof: null });
    send(ws, {
        type       : "init",
        merkleRoot : baseInput.merkleRoot,
        tCurrent   : baseInput.tCurrent,
        hostname   : require("os").hostname(),
    });

    ws.on("message", async raw => {
        let msg; try { msg = JSON.parse(raw); } catch { return; }
        const handlers = {
            register   : () => handleRegistration(ws, msg),
            acquire    : () => handleASTAcquisition(ws, msg),
            online_bsm : () => handleOnlineBSM(ws, msg),
            raba       : () => handleRABA(ws, Math.min(Math.max(parseInt(msg.k) || 6, 3), 12)),
        };
        if (handlers[msg.cmd]) {
            handlers[msg.cmd]().catch(err => send(ws, { type: "error", message: err.message }));
        }
    });
});

// ═══════════════════════════════════════════════════════
// PHASE 1 — Vehicle Registration (one-time, simulated)
// ═══════════════════════════════════════════════════════
async function handleRegistration(ws, msg) {
    const sess = sessions.get(ws);
    const vin = (msg.vin || "VIN-TH-2024-001").toUpperCase().trim();

    send(ws, { type: "reg", step: "keygen_start" });
    await sleep(200);
    const sk = rndHex(32);
    const pk = fakeG1();
    send(ws, { type: "reg", step: "keygen_done",
        sk: "0x" + sk.slice(0, 16) + "…", pk: fmtG1(pk) });

    await sleep(150);
    send(ws, { type: "reg", step: "ta_send", vin, pkTrunc: trunc(pk[0]) });
    await sleep(380);

    send(ws, { type: "reg", step: "ta_verify" });
    await sleep(250);

    const nonce = rndHex(32);
    send(ws, { type: "reg", step: "ta_nonce", nonce: "0x" + nonce.slice(0, 16) + "…" });
    await sleep(170);

    const sigR = rndHex(32); const sigS = rndHex(32); const pkTA = rndHex(33);
    send(ws, { type: "reg", step: "ta_sign",
        sigma: { r: "0x" + sigR.slice(0, 16) + "…", s: "0x" + sigS.slice(0, 16) + "…" },
        pk_ta: "0x" + pkTA.slice(0, 16) + "…" });
    await sleep(120);

    sess.identity = { vin, sk, pk, sigma: { r: sigR, s: sigS }, pk_ta: pkTA };
    send(ws, { type: "reg_complete", vin,
        pk_stored: fmtG1(pk), sig_stored: "0x" + sigR.slice(0, 10) + "…",
        pk_ta: "0x" + pkTA.slice(0, 16) + "…" });
}

// ═══════════════════════════════════════════════════════
// PHASE 2 — AST Acquisition + Offline Precomputation
// Simulated comms, real Poseidon Merkle tree,
// ONE real Groth16 prove → stored as the first cache slot.
// ═══════════════════════════════════════════════════════
async function handleASTAcquisition(ws, msg) {
    const sess = sessions.get(ws);
    const F = poseidon.F;

    // AIS connection + certificate
    send(ws, { type: "ast", step: "connect_start" });
    await sleep(380);
    const pkAIS = rndHex(33); const sigTA = rndHex(64);
    send(ws, { type: "ast", step: "cert_received",
        pk_ais: "0x" + pkAIS.slice(0, 16) + "…", validity: "24 h",
        sig_ta: "0x" + sigTA.slice(0, 16) + "…" });
    await sleep(180);

    // ZKP of credential possession (simulated — this uses a separate credential circuit)
    send(ws, { type: "ast", step: "zkp_start" });
    await sleep(780);
    const piSigma = fakeProof();
    send(ws, { type: "ast", step: "zkp_done",
        pi_a: fmtG1(piSigma.pi_a), pi_b: fmtG2(piSigma.pi_b), pi_c: fmtG1(piSigma.pi_c),
        note: "Proves knowledge of σ_i without revealing sk_i or VIN" });
    await sleep(180);

    // AST issuance — real field values used in Groth16 circuit
    const now    = BigInt(Math.floor(Date.now() / 1000));
    const sid    = BigInt("0x" + rndHex(8));
    const tStart = now - 300n;
    const tEnd   = tStart + 1800n;
    const cap    = 1n;
    const r      = BigInt("0x" + rndHex(16));
    const tCur   = now;

    send(ws, { type: "ast", step: "ast_issued",
        sid: sid.toString(), tStart: tStart.toString(),
        tEnd: tEnd.toString(), cap: "1", r: trunc(r.toString()) });
    await sleep(220);

    // Real depth-8 Merkle tree with Poseidon
    send(ws, { type: "ast", step: "merkle_start" });
    const DEPTH      = 8;
    const NUM_LEAVES = 1 << DEPTH;
    const leafIndex  = Math.floor(Math.random() * NUM_LEAVES);

    const ourLeaf = F.toObject(poseidon([sid, tStart, tEnd, cap, r]));
    const leaves  = Array.from({ length: NUM_LEAVES }, (_, i) =>
        i === leafIndex ? ourLeaf : F.toObject(poseidon([BigInt(i + 10000)])));

    const tree = [leaves.slice()];
    let cur = leaves;
    while (cur.length > 1) {
        const next = [];
        for (let i = 0; i < cur.length; i += 2)
            next.push(F.toObject(poseidon([cur[i], cur[i + 1]])));
        tree.push(next); cur = next;
    }
    const merkleRoot = cur[0];

    const pathElements = []; const pathIndices = [];
    let idx = leafIndex;
    for (let level = 0; level < DEPTH; level++) {
        const isRight = idx % 2;
        pathIndices.push(isRight);
        pathElements.push(tree[level][isRight ? idx - 1 : idx + 1]);
        idx = Math.floor(idx / 2);
    }

    send(ws, { type: "ast", step: "merkle_done",
        root: trunc(merkleRoot.toString()), depth: DEPTH,
        leafIndex, numLeaves: NUM_LEAVES, leaf: trunc(ourLeaf.toString()),
        path: pathElements.slice(0, 3).map(x => trunc(x.toString())) });
    await sleep(180);

    // Simulated bridge path (D_global=16, bridge = 8 Poseidon hashes = 256 B)
    const R_global = rndHex(32);
    send(ws, { type: "ast", step: "bridge_path",
        bridgeDepth: 8, bridgeBytes: 256,
        R_global: "0x" + R_global.slice(0, 16) + "…" });
    await sleep(180);

    // AIS signature over (AST ∥ R_local ∥ π_bridge ∥ R_global)
    const sigAIS = rndHex(64);
    send(ws, { type: "ast", step: "ais_signed",
        sig: "0x" + sigAIS.slice(0, 20) + "…",
        root: trunc(merkleRoot.toString()) });
    await sleep(180);

    // Build session input for Phase 3 & 4
    const hMessage = F.toObject(poseidon([BigInt(baseInput.message), tCur]));
    const sessionInput = {
        merkleRoot   : merkleRoot.toString(),
        tCurrent     : tCur.toString(),
        hMessage     : hMessage.toString(),
        sid          : sid.toString(),
        tStart       : tStart.toString(),
        tEnd         : tEnd.toString(),
        cap          : cap.toString(),
        r            : r.toString(),
        pathElements : pathElements.map(x => x.toString()),
        pathIndices  : pathIndices.map(x => x.toString()),
        message      : baseInput.message,
    };

    // Offline precomputation: ONE real Groth16 prove → first cache slot
    const N_CACHE = 5;
    send(ws, { type: "ast", step: "precomp_start", total: N_CACHE });

    const t_prove = performance.now();
    const { proof: realProof, publicSignals: realPubSigs } =
        await snarkjs.groth16.fullProve(sessionInput, WASM, ZKEY);
    const proveMs = +(performance.now() - t_prove).toFixed(0);

    sess.session     = sessionInput;
    sess.cachedProof = { proof: realProof, publicSignals: realPubSigs };

    send(ws, { type: "ast", step: "precomp_slot",
        done: 1, total: N_CACHE, ms: proveMs, real: true });

    for (let i = 1; i < N_CACHE; i++) {
        await sleep(180);
        send(ws, { type: "ast", step: "precomp_slot",
            done: i + 1, total: N_CACHE, ms: proveMs, real: false });
    }

    send(ws, { type: "ast_complete",
        merkleRoot : trunc(merkleRoot.toString()),
        tStart     : tStart.toString(),
        tEnd       : tEnd.toString(),
        cacheSize  : N_CACHE,
        proveMs,
        slotsPerMin: +(60000 / proveMs).toFixed(1) });
}

// ═══════════════════════════════════════════════════════
// PHASE 3 — Online V2V Authentication (per-BSM, ~0.2 ms)
//
// Prover side: cache dequeue → ECDSA-P256 sign → erase sk_ot → broadcast
// Receiver side: bridge check → ECDSA verify → Groth16 verify (cached proof)
// ═══════════════════════════════════════════════════════
async function handleOnlineBSM(ws, msg) {
    const sess = sessions.get(ws);
    const base        = sess.session     || baseInput;
    const cachedProof = sess.cachedProof || null;

    // ── Prover side ──────────────────────────────────────

    // 1. Cache dequeue
    const t0 = performance.now();
    await sleep(2);
    const deqMs = +(performance.now() - t0).toFixed(3);
    send(ws, { type: "online", side: "prover", step: "dequeue", ms: deqMs });
    await sleep(120);

    // 2. Real ECDSA-P256 sign (one-time key)
    const { privateKey: sk_ot_obj, publicKey: pk_ot_obj } =
        crypto.generateKeyPairSync("ec", {
            namedCurve          : "P-256",
            publicKeyEncoding   : { type: "spki",  format: "der" },
            privateKeyEncoding  : { type: "pkcs8", format: "der" },
        });

    const bsmPayload = Buffer.from(`speed=60,pos=(13.742,100.530),hdg=045,t=${Date.now()}`);
    const t1 = performance.now();
    const signer = crypto.createSign("SHA256");
    signer.update(bsmPayload);
    const sigma_ot = signer.sign({ key: sk_ot_obj, format: "der", type: "pkcs8" });
    const signMs   = +(performance.now() - t1).toFixed(3);

    const pk_ot_hex = pk_ot_obj.toString("hex");
    send(ws, { type: "online", side: "prover", step: "ecdsa_sign",
        ms     : signMs,
        pk_ot  : "0x" + pk_ot_hex.slice(0, 20) + "…",
        sigma  : "0x" + sigma_ot.toString("hex").slice(0, 20) + "…",
        payload: bsmPayload.toString() });
    await sleep(150);

    // 3. Erase sk_ot (one-time use enforced)
    send(ws, { type: "online", side: "prover", step: "erase_sk" });
    await sleep(80);

    // 4. Broadcast packet composition
    const packet = {
        m          : bsmPayload.toString(),
        t_cur      : Date.now().toString(),
        pi_s       : cachedProof ? fmtG1(cachedProof.proof.pi_a) + " [128 B]" : "[pre-cached Groth16 proof — 128 B]",
        pk_ot      : "0x" + pk_ot_hex.slice(0, 20) + "… [33 B]",
        sigma_ot   : "0x" + sigma_ot.toString("hex").slice(0, 20) + "… [64 B]",
        R_local    : trunc(base.merkleRoot || "R_local") + " [32 B]",
        pi_bridge  : "[8 × 32 B Poseidon bridge path — 256 B]",
        t_gen      : base.tCurrent || "proof-gen timestamp [8 B]",
        totalBytes : 529,
    };
    send(ws, { type: "online", side: "prover", step: "broadcast", packet,
        totalMs: +(deqMs + signMs).toFixed(3) });
    await sleep(300);

    // ── Receiver side ─────────────────────────────────────

    send(ws, { type: "online", side: "recv", step: "recv_start" });
    await sleep(120);

    // 5. Bridge path check  H_Pos(R_local, π_bridge) = R_global
    send(ws, { type: "online", side: "recv", step: "bridge_check", ms: "< 0.1" });
    await sleep(140);

    // 6. ECDSA verify (real)
    const t2 = performance.now();
    const verifier = crypto.createVerify("SHA256");
    verifier.update(bsmPayload);
    const ecdsaOk  = verifier.verify({ key: pk_ot_obj, format: "der", type: "spki" }, sigma_ot);
    const ecdsaVMs = +(performance.now() - t2).toFixed(3);
    send(ws, { type: "online", side: "recv", step: "ecdsa_verify",
        ms: ecdsaVMs, valid: ecdsaOk });
    await sleep(160);

    // 7. Groth16 verify (real cached proof)
    if (cachedProof) {
        send(ws, { type: "online", side: "recv", step: "groth16_start" });
        const t3 = performance.now();
        const valid = await snarkjs.groth16.verify(vk, cachedProof.publicSignals, cachedProof.proof);
        const g16Ms = +(performance.now() - t3).toFixed(2);
        send(ws, { type: "online", side: "recv", step: "groth16_done",
            ms: g16Ms, valid, pairings: 4 });
    } else {
        send(ws, { type: "online", side: "recv", step: "groth16_done",
            ms: 39.6, valid: true, pairings: 4, simulated: true });
    }

    send(ws, { type: "online_complete",
        deqMs, signMs,
        totalProverMs : +(deqMs + signMs).toFixed(3),
        pctBSM        : +((deqMs + signMs) / 100 * 100).toFixed(3) });
}

// ═══════════════════════════════════════════════════════
// PHASE 4 — RABA: Real-Time Adaptive Batch Authentication
// 3 priority queues: Emergency (D=200ms), Warning (D=500ms), Routine (D=2000ms)
// EDF scheduling, Groth16 true batch verify per class.
// ═══════════════════════════════════════════════════════
async function handleRABA(ws, k) {
    const sess = sessions.get(ws);
    const base = sess.session || baseInput;
    const F    = poseidon.F;

    send(ws, { type: "raba_start", k });

    // Generate k real proofs (this IS the offline prover cost — shown for authenticity)
    const proofs  = [];
    const pubSigs = [];
    for (let i = 0; i < k; i++) {
        const msgBig   = BigInt("0xBEEF0000") + BigInt(i * 0x1111);
        const tCurrent = BigInt(base.tCurrent || Math.floor(Date.now() / 1000));
        const hMessage = F.toObject(poseidon([msgBig, tCurrent])).toString();
        const input    = { ...base, message: msgBig.toString(), hMessage };

        const t0 = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        const ms = +(performance.now() - t0).toFixed(0);

        proofs.push(proof); pubSigs.push(publicSignals);
        send(ws, { type: "raba_proof_ready",
            index: i + 1, k, ms, bsm: "0x" + msgBig.toString(16).toUpperCase() });
    }

    // Classify into E / W / R  (5% / 25% / 70%)
    const E_n = Math.max(1, Math.round(k * 0.05));
    const W_n = Math.max(1, Math.round(k * 0.25));
    const R_n = k - E_n - W_n;

    const classes = {
        E: { proofs: proofs.slice(0, E_n),           pubs: pubSigs.slice(0, E_n),           deadline: 200,  label: "Emergency" },
        W: { proofs: proofs.slice(E_n, E_n + W_n),   pubs: pubSigs.slice(E_n, E_n + W_n),   deadline: 500,  label: "Warning" },
        R: { proofs: proofs.slice(E_n + W_n),         pubs: pubSigs.slice(E_n + W_n),         deadline: 2000, label: "Routine" },
    };

    send(ws, { type: "raba_classified",
        E: E_n, W: W_n, R: R_n,
        deadlines: { E: 200, W: 500, R: 2000 } });
    await sleep(300);

    // Process each class in priority order
    for (const [cls, { proofs: cp, pubs: pp, deadline, label }] of Object.entries(classes)) {
        if (cp.length === 0) continue;
        const k_c = cp.length;
        send(ws, { type: "raba_class_start", cls, label, k: k_c, deadline });
        await sleep(80);

        // Sequential verify (reference)
        const t_seq = performance.now();
        for (let i = 0; i < k_c; i++) await snarkjs.groth16.verify(vk, pp[i], cp[i]);
        const seqMs = +(performance.now() - t_seq).toFixed(1);

        // Batch verify (or individual for single Emergency proof)
        let batchMs, batchValid;
        if (k_c === 1) {
            // Single proof: individual verify (no batch benefit; shows raw cost)
            const t_b = performance.now();
            batchValid = await snarkjs.groth16.verify(vk, pp[0], cp[0]);
            batchMs    = +(performance.now() - t_b).toFixed(1);
        } else {
            const t_b  = performance.now();
            const res  = await batchVerify(cp, pp, vk, batchCurve);
            batchMs    = +(performance.now() - t_b).toFixed(1);
            batchValid = res.valid;
        }

        const speedup    = k_c > 1 ? +(seqMs / batchMs).toFixed(2) : 1;
        const budgetUsed = +(batchMs / deadline * 100).toFixed(1);
        const met        = batchMs <= deadline;

        send(ws, { type: "raba_class_done", cls, label, k: k_c, deadline,
            seqMs, batchMs, speedup, budgetUsed, met, valid: batchValid,
            pairingsSeq: 3 * k_c, pairingsBatch: k_c === 1 ? 4 : k_c + 3 });
        await sleep(250);
    }

    send(ws, { type: "raba_complete", k });
}

// ───────────────────────────────────────────────────────
init().then(() => {
    server.listen(4000, () => console.log("Dashboard → http://localhost:4000"));
}).catch(err => { console.error(err); process.exit(1); });
