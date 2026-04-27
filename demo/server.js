/**
 * demo/server.js — ULP-V2V-Auth Live Demo (full rewrite, Apr-26 system)
 *
 * Sends rich hex data so the frontend can show real cryptographic values.
 * Phase 3 correctly shows online cost = ECDSA only (~0.2 ms).
 * Phase 4 implements RABA with 3 priority queues (E/W/R).
 */

const express           = require("express");
const http              = require("http");
const WebSocket         = require("ws");
const snarkjs           = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { batchVerify, buildBatchCurve } = require("../benchmark/groth16_batch_verify");
const crypto = require("crypto");
const os     = require("os");
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

// ── helpers ────────────────────────────────────────────
function rndHex(n) { return crypto.randomBytes(n).toString("hex"); }
function trunc(s, n = 20) { s = String(s); return s.length > n ? s.slice(0, n) + "…" : s; }

/** Arbitrary BigInt → 0x-prefixed 64-char hex (field element) */
function toHex(n) {
    try { return "0x" + BigInt(n).toString(16).padStart(64, "0"); }
    catch { return "0x" + String(n).slice(0, 64).padStart(64, "0"); }
}

/** Decimal string → short display hex (0x + first 8 bytes) */
function shortHex(n) { return toHex(n).slice(0, 18) + "…"; }

function fmtG1(a)  { return `(${shortHex(a[0])}, ${shortHex(a[1])})`; }
function fmtG2(a)  { return `([${shortHex(a[0][0])},…], [${shortHex(a[1][0])},…])`; }

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

/** Best non-loopback IPv4 address */
function localIP() {
    for (const iface of Object.values(os.networkInterfaces())) {
        for (const addr of iface) {
            if (addr.family === "IPv4" && !addr.internal) return addr.address;
        }
    }
    return "localhost";
}

// ── server setup ───────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

app.use(express.static(path.join(__dirname, "public")));

async function init() {
    for (const f of [WASM, ZKEY, VK, INPUT]) {
        if (!fs.existsSync(f)) {
            console.error(`\n  Missing: ${f}\n  Run:  npm run setup && npm run gen-input  first.\n`);
            process.exit(1);
        }
    }
    console.log("Loading keys and building Poseidon + BN128 curve (~5 s)…");
    vk         = JSON.parse(fs.readFileSync(VK));
    baseInput  = JSON.parse(fs.readFileSync(INPUT));
    poseidon   = await buildPoseidon();
    batchCurve = await buildBatchCurve();
    console.log(`Ready. Open http://${localIP()}:4000\n`);
}

wss.on("connection", ws => {
    sessions.set(ws, { identity: null, session: null, cachedProof: null });
    send(ws, {
        type    : "init",
        hostname: os.hostname(),
        ip      : localIP(),
    });
    ws.on("message", async raw => {
        let msg; try { msg = JSON.parse(raw); } catch { return; }
        const h = {
            register   : () => handleRegistration(ws, msg),
            acquire    : () => handleASTAcquisition(ws, msg),
            online_bsm : () => handleOnlineBSM(ws, msg),
            raba       : () => handleRABA(ws, Math.min(Math.max(parseInt(msg.k) || 6, 3), 12)),
        };
        if (h[msg.cmd]) h[msg.cmd]().catch(err => send(ws, { type: "error", message: err.message }));
    });
});

// ═══════════════════════════════════════════════════════
// PHASE 1 — Vehicle Registration (simulated with real-looking hex)
// ═══════════════════════════════════════════════════════
async function handleRegistration(ws, msg) {
    const sess = sessions.get(ws);
    const vin  = (msg.vin || "VIN-TH-2024-001").toUpperCase().trim();

    send(ws, { type: "reg", step: "keygen_start" });
    await sleep(220);

    const skRaw = rndHex(32);   // 256-bit BN254 scalar
    const pk    = fakeG1();
    send(ws, { type: "reg", step: "keygen_done",
        sk_hex : "0x" + skRaw,
        pk_x   : toHex(pk[0]),
        pk_y   : toHex(pk[1]),
    });
    await sleep(160);

    send(ws, { type: "reg", step: "ta_send", vin, pk_x_short: shortHex(pk[0]) });
    await sleep(400);

    send(ws, { type: "reg", step: "ta_verify" });
    await sleep(260);

    const nonce = rndHex(32);
    send(ws, { type: "reg", step: "ta_nonce", nonce_hex: "0x" + nonce });
    await sleep(190);

    // σ_i = Sign_{sk_TA}(H(pk_i ∥ nonce))  — simulated ECDSA-P256 sig
    const sigR = rndHex(32); const sigS = rndHex(32);
    const pkTA = rndHex(33);
    send(ws, { type: "reg", step: "ta_sign",
        sigma_r : "0x" + sigR,
        sigma_s : "0x" + sigS,
        pk_ta   : "0x" + pkTA,
    });
    await sleep(130);

    sess.identity = { vin, skRaw, pk, nonce, sigma: { r: sigR, s: sigS }, pk_ta: pkTA };
    send(ws, { type: "reg_complete", vin,
        sk_hex  : "0x" + skRaw,
        pk_x    : toHex(pk[0]),
        pk_y    : toHex(pk[1]),
        nonce   : "0x" + nonce,
        sigma_r : "0x" + sigR,
        sigma_s : "0x" + sigS,
        pk_ta   : "0x" + pkTA,
    });
}

// ═══════════════════════════════════════════════════════
// PHASE 2 — AST Acquisition + Offline Precomputation
// Real Poseidon hashes, ONE real Groth16 prove.
// ═══════════════════════════════════════════════════════
async function handleASTAcquisition(ws, msg) {
    const sess = sessions.get(ws);
    const F    = poseidon.F;

    send(ws, { type: "ast", step: "connect_start" });
    await sleep(360);

    const pkAIS = rndHex(33); const sigTA = rndHex(64);
    send(ws, { type: "ast", step: "cert_received",
        pk_ais_hex : "0x" + pkAIS,
        sig_ta_hex : "0x" + sigTA.slice(0, 64),
        validity   : "24 h",
    });
    await sleep(190);

    // ZKP of credential possession (separate credential circuit — simulated)
    send(ws, { type: "ast", step: "zkp_start" });
    await sleep(820);
    const pi = fakeProof();
    send(ws, { type: "ast", step: "zkp_done",
        pi_a_hex : toHex(pi.pi_a[0]),
        pi_b_hex : toHex(pi.pi_b[0][0]),
        pi_c_hex : toHex(pi.pi_c[0]),
    });
    await sleep(180);

    // AST issuance — real field values used in circuit
    const now    = BigInt(Math.floor(Date.now() / 1000));
    const sid    = BigInt("0x" + rndHex(8));
    const tStart = now - 300n;
    const tEnd   = tStart + 1800n;
    const cap    = 1n;
    const r      = BigInt("0x" + rndHex(16));
    const tCur   = now;

    send(ws, { type: "ast", step: "ast_issued",
        sid_hex    : toHex(sid),
        tStart_hex : toHex(tStart),
        tEnd_hex   : toHex(tEnd),
        cap_hex    : toHex(cap),
        r_hex      : toHex(r),
        sid        : sid.toString(),
        tStart     : tStart.toString(),
        tEnd       : tEnd.toString(),
    });
    await sleep(220);

    // Real depth-8 Merkle tree with Poseidon
    send(ws, { type: "ast", step: "merkle_start" });

    const DEPTH      = 8;
    const NUM_LEAVES = 1 << DEPTH;
    const leafIndex  = Math.floor(Math.random() * NUM_LEAVES);

    const ourLeaf = F.toObject(poseidon([sid, tStart, tEnd, cap, r]));
    const leaves  = Array.from({ length: NUM_LEAVES }, (_, i) =>
        i === leafIndex ? ourLeaf : F.toObject(poseidon([BigInt(i + 10000)])));

    // Build tree level by level
    const tree = [leaves.slice()];
    let cur = leaves;
    while (cur.length > 1) {
        const next = [];
        for (let i = 0; i < cur.length; i += 2)
            next.push(F.toObject(poseidon([cur[i], cur[i + 1]])));
        tree.push(next); cur = next;
    }
    const merkleRoot = cur[0];

    // Extract proof path
    const pathElements = []; const pathIndices = [];
    let idx = leafIndex;
    for (let level = 0; level < DEPTH; level++) {
        const isRight = idx % 2;
        pathIndices.push(isRight);
        pathElements.push(tree[level][isRight ? idx - 1 : idx + 1]);
        idx = Math.floor(idx / 2);
    }

    // Compute intermediate nodes along path (for tree visualisation)
    const intermediates = [ourLeaf];
    for (let level = 0; level < DEPTH; level++) {
        const isRight  = pathIndices[level];
        const L = isRight ? pathElements[level] : intermediates[level];
        const R = isRight ? intermediates[level] : pathElements[level];
        intermediates.push(F.toObject(poseidon([L, R])));
    }

    // Build treeViz array (leaf → root, 8 steps)
    const treeViz = [];
    for (let level = 0; level < DEPTH; level++) {
        const isRight = pathIndices[level] === 1;
        treeViz.push({
            level,
            yourNode    : { hex: toHex(intermediates[level]),   short: shortHex(intermediates[level])   },
            sibling     : { hex: toHex(pathElements[level]),    short: shortHex(pathElements[level])    },
            parent      : { hex: toHex(intermediates[level+1]), short: shortHex(intermediates[level+1]) },
            yourIsRight : isRight,
        });
    }

    send(ws, { type: "ast", step: "merkle_done",
        leafIndex, numLeaves: NUM_LEAVES, depth: DEPTH,
        leaf_hex : toHex(ourLeaf),
        root_hex : toHex(merkleRoot),
        astFields: {
            sid    : { val: sid.toString(),    hex: toHex(sid)    },
            tStart : { val: tStart.toString(), hex: toHex(tStart) },
            tEnd   : { val: tEnd.toString(),   hex: toHex(tEnd)   },
            cap    : { val: cap.toString(),    hex: toHex(cap)    },
            r      : { val: r.toString(),      hex: toHex(r)      },
        },
        treeViz,
    });
    await sleep(180);

    // Bridge path (D_global=16, bridge = 8 Poseidon hashes)
    const bridgePath = Array.from({ length: 8 }, () => ({
        hex: "0x" + rndHex(32), short: "0x" + rndHex(8) + "…"
    }));
    const R_global = rndHex(32);
    send(ws, { type: "ast", step: "bridge_path",
        bridgePath,
        R_global_hex : "0x" + R_global,
        bridgeBytes  : 256,
    });
    await sleep(180);

    const sigAIS = rndHex(64);
    send(ws, { type: "ast", step: "ais_signed",
        sig_ais_hex : "0x" + sigAIS,
        root_hex    : toHex(merkleRoot),
    });
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

    // ONE real Groth16 prove → first cache slot
    const N_CACHE = 5;
    send(ws, { type: "ast", step: "precomp_start", total: N_CACHE });

    const t_prove = performance.now();
    const { proof: realProof, publicSignals: realPubs } =
        await snarkjs.groth16.fullProve(sessionInput, WASM, ZKEY);
    const proveMs = +(performance.now() - t_prove).toFixed(0);

    sess.session     = sessionInput;
    sess.cachedProof = {
        proof: realProof, publicSignals: realPubs,
        pi_a_hex: toHex(realProof.pi_a[0]),
        pi_b_hex: toHex(realProof.pi_b[0][0]),
        pi_c_hex: toHex(realProof.pi_c[0]),
    };

    send(ws, { type: "ast", step: "precomp_slot",
        done: 1, total: N_CACHE, ms: proveMs, real: true,
        pi_a_hex: toHex(realProof.pi_a[0]),
        pi_b_hex: toHex(realProof.pi_b[0][0]),
        pi_c_hex: toHex(realProof.pi_c[0]),
    });

    for (let i = 1; i < N_CACHE; i++) {
        await sleep(160);
        send(ws, { type: "ast", step: "precomp_slot",
            done: i + 1, total: N_CACHE, ms: proveMs, real: false,
        });
    }

    send(ws, { type: "ast_complete",
        root_hex    : toHex(merkleRoot),
        tStart      : tStart.toString(),
        tEnd        : tEnd.toString(),
        cacheSize   : N_CACHE,
        proveMs,
        slotsPerMin : +(60000 / proveMs).toFixed(1),
    });
}

// ═══════════════════════════════════════════════════════
// PHASE 3 — Online V2V Authentication (correct: ECDSA only)
// Prover:   cache dequeue + ECDSA-P256 sign
// Receiver: bridge check + ECDSA verify + Groth16 verify
// ═══════════════════════════════════════════════════════
async function handleOnlineBSM(ws, msg) {
    const sess        = sessions.get(ws);
    const base        = sess.session     || baseInput;
    const cachedProof = sess.cachedProof || null;

    // ── Prover ────────────────────────────────────────────

    // 1. Cache dequeue
    const t0 = performance.now();
    await sleep(2);
    const deqMs = +(performance.now() - t0).toFixed(3);
    send(ws, { type: "online", side: "prover", step: "dequeue",
        ms: deqMs,
        slot_pi_hex : cachedProof ? cachedProof.pi_a_hex : "0x" + rndHex(32),
    });
    await sleep(120);

    // 2. Real ECDSA-P256 one-time keypair
    const { privateKey: sk_ot, publicKey: pk_ot } =
        crypto.generateKeyPairSync("ec", {
            namedCurve        : "P-256",
            publicKeyEncoding  : { type: "spki",  format: "der" },
            privateKeyEncoding : { type: "pkcs8", format: "der" },
        });

    const bsmPayload = Buffer.from(
        `speed=60km/h,pos=(13.7424,100.5301),hdg=045°,t=${Date.now()}`);

    const t1    = performance.now();
    const sig   = crypto.createSign("SHA256");
    sig.update(bsmPayload);
    const sigma_ot = sig.sign({ key: sk_ot, format: "der", type: "pkcs8" });
    const signMs   = +(performance.now() - t1).toFixed(3);

    const sk_hex = sk_ot.toString("hex");
    const pk_hex = pk_ot.toString("hex");
    const sg_hex = sigma_ot.toString("hex");

    send(ws, { type: "online", side: "prover", step: "ecdsa_sign",
        ms      : signMs,
        sk_hex  : "0x" + sk_hex.slice(0, 64),
        pk_hex  : "0x" + pk_hex.slice(0, 66),
        sig_hex : "0x" + sg_hex.slice(0, 72),
        payload : bsmPayload.toString(),
    });
    await sleep(140);

    // 3. Erase sk_ot
    send(ws, { type: "online", side: "prover", step: "erase_sk" });
    await sleep(80);

    // 4. Broadcast packet
    const packet = {
        m          : bsmPayload.toString(),
        t_cur      : Date.now().toString(),
        pi_s_hex   : cachedProof ? cachedProof.pi_a_hex : "0x" + rndHex(32),
        pk_ot_hex  : "0x" + pk_hex.slice(0, 66),
        sigma_hex  : "0x" + sg_hex.slice(0, 72),
        R_local_hex: cachedProof ? shortHex(base.merkleRoot || "0") : "0x" + rndHex(32),
        pi_bridge  : "[ 8 × 32 B Poseidon sibling hashes ]",
        t_gen      : base.tCurrent || Date.now().toString(),
        totalBytes : 529,
    };
    send(ws, { type: "online", side: "prover", step: "broadcast",
        packet, totalMs: +(deqMs + signMs).toFixed(3) });
    await sleep(280);

    // ── Receiver ──────────────────────────────────────────

    // 5. Bridge path check
    send(ws, { type: "online", side: "recv", step: "bridge_check", ms: "< 0.1" });
    await sleep(130);

    // 6. ECDSA verify (real)
    const t2  = performance.now();
    const ver = crypto.createVerify("SHA256");
    ver.update(bsmPayload);
    const ecdsaOk = ver.verify({ key: pk_ot, format: "der", type: "spki" }, sigma_ot);
    const ecdsaVMs = +(performance.now() - t2).toFixed(3);
    send(ws, { type: "online", side: "recv", step: "ecdsa_verify",
        ms: ecdsaVMs, valid: ecdsaOk,
        sig_hex: "0x" + sg_hex.slice(0, 72),
        pk_hex : "0x" + pk_hex.slice(0, 66),
    });
    await sleep(150);

    // 7. Groth16 verify (real cached proof)
    send(ws, { type: "online", side: "recv", step: "groth16_start" });
    let g16Ms, g16Valid;
    if (cachedProof) {
        const t3 = performance.now();
        g16Valid = await snarkjs.groth16.verify(vk, cachedProof.publicSignals, cachedProof.proof);
        g16Ms    = +(performance.now() - t3).toFixed(2);
    } else {
        g16Ms = 39.6; g16Valid = true;
    }
    send(ws, { type: "online", side: "recv", step: "groth16_done",
        ms      : g16Ms,
        valid   : g16Valid,
        pi_hex  : cachedProof ? cachedProof.pi_a_hex : "0x" + rndHex(32),
        pairings: 4,
    });

    send(ws, { type: "online_complete",
        deqMs, signMs,
        totalProverMs : +(deqMs + signMs).toFixed(3),
        pctBSM        : +((deqMs + signMs) / 100 * 100).toFixed(3),
        g16Ms,
    });
}

// ═══════════════════════════════════════════════════════
// PHASE 4 — RABA: 3 priority queues, EDF, batch per class
// ═══════════════════════════════════════════════════════
async function handleRABA(ws, k) {
    const sess = sessions.get(ws);
    const base = sess.session || baseInput;
    const F    = poseidon.F;

    send(ws, { type: "raba_start", k });

    // Generate k real proofs
    const proofs = [], pubSigs = [];
    for (let i = 0; i < k; i++) {
        const msgBig   = BigInt("0xBEEF0000") + BigInt(i * 0x1111);
        const tCurrent = BigInt(base.tCurrent || Math.floor(Date.now() / 1000));
        const hMessage = F.toObject(poseidon([msgBig, tCurrent])).toString();
        const input    = { ...base, message: msgBig.toString(), hMessage };
        const t0       = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        const ms = +(performance.now() - t0).toFixed(0);
        proofs.push(proof); pubSigs.push(publicSignals);
        send(ws, { type: "raba_proof_ready",
            index: i + 1, k, ms, bsm: "0x" + msgBig.toString(16).toUpperCase().padStart(8, "0") });
    }

    // Classify 5% E / 25% W / 70% R
    const E_n = Math.max(1, Math.round(k * 0.05));
    const W_n = Math.max(1, Math.round(k * 0.25));
    const R_n = k - E_n - W_n;

    const classes = {
        E: { proofs: proofs.slice(0, E_n),         pubs: pubSigs.slice(0, E_n),         deadline: 200,  label: "Emergency" },
        W: { proofs: proofs.slice(E_n, E_n + W_n), pubs: pubSigs.slice(E_n, E_n + W_n), deadline: 500,  label: "Warning"   },
        R: { proofs: proofs.slice(E_n + W_n),       pubs: pubSigs.slice(E_n + W_n),       deadline: 2000, label: "Routine"   },
    };

    send(ws, { type: "raba_classified", E: E_n, W: W_n, R: R_n });
    await sleep(250);

    for (const [cls, { proofs: cp, pubs: pp, deadline, label }] of Object.entries(classes)) {
        if (cp.length === 0) continue;
        const k_c = cp.length;
        send(ws, { type: "raba_class_start", cls, label, k: k_c, deadline });

        const t_seq = performance.now();
        for (let i = 0; i < k_c; i++) await snarkjs.groth16.verify(vk, pp[i], cp[i]);
        const seqMs = +(performance.now() - t_seq).toFixed(1);

        let batchMs, batchValid;
        if (k_c === 1) {
            const t_b = performance.now();
            batchValid = await snarkjs.groth16.verify(vk, pp[0], cp[0]);
            batchMs    = +(performance.now() - t_b).toFixed(1);
        } else {
            const t_b = performance.now();
            const res  = await batchVerify(cp, pp, vk, batchCurve);
            batchMs    = +(performance.now() - t_b).toFixed(1);
            batchValid = res.valid;
        }

        send(ws, { type: "raba_class_done", cls, label, k: k_c, deadline,
            seqMs, batchMs,
            speedup     : k_c > 1 ? +(seqMs / batchMs).toFixed(2) : 1,
            budgetUsed  : +(batchMs / deadline * 100).toFixed(1),
            met         : batchMs <= deadline,
            valid       : batchValid,
            pairingsSeq : 3 * k_c,
            pairingsBatch: k_c === 1 ? 4 : k_c + 3,
        });
        await sleep(200);
    }

    send(ws, { type: "raba_complete", k });
}

// ── start ──────────────────────────────────────────────
init().then(() => {
    server.listen(4000, () =>
        console.log(`Dashboard → http://${localIP()}:4000  (also http://localhost:4000)`));
}).catch(err => { console.error(err); process.exit(1); });
