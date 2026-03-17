/**
 * demo/server.js
 *
 * Live dashboard server for ULP-V2V-Auth — all four phases.
 *
 * Phase 1 & 2 are simulated with realistic delays and fake-but-plausible
 * cryptographic values. Phase 2 uses REAL Poseidon hashing so the Merkle
 * root it produces is a genuine proof-system value that feeds directly into
 * Phase 3. Phase 3 & 4 run the real Groth16 prover/verifier.
 *
 * Run:  npm run demo
 *       then open http://localhost:4000
 */

const express   = require("express");
const http      = require("http");
const WebSocket = require("ws");
const snarkjs   = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { batchVerify, buildBatchCurve } = require("../benchmark/groth16_batch_verify");
const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");

// -------------------------------------------------------
// Paths
// -------------------------------------------------------
const ROOT  = path.join(__dirname, "..");
const WASM  = path.join(ROOT, "build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY  = path.join(ROOT, "keys",  "ulp_v2v_auth_final.zkey");
const VK    = path.join(ROOT, "keys",  "verification_key.json");
const INPUT = path.join(ROOT, "build", "input.json");

// -------------------------------------------------------
// Globals
// -------------------------------------------------------
let vk, baseInput, poseidon, batchCurve;

// Per-connection session:  ws → { identity, currentInput }
const sessions = new WeakMap();

// -------------------------------------------------------
// Helpers
// -------------------------------------------------------
const sleep = ms => new Promise(r => setTimeout(r, ms));

/** Random hex string of `bytes` bytes. */
function rndHex(bytes) {
    return crypto.randomBytes(bytes).toString("hex");
}

/** Fake BN254 G1 point — realistic 32-byte field elements as decimal strings. */
function fakeG1() {
    const x = BigInt("0x" + rndHex(31)) % BigInt("21888242871839275222246405745257275088696311157297823662689037894645226208583");
    const y = BigInt("0x" + rndHex(31)) % BigInt("21888242871839275222246405745257275088696311157297823662689037894645226208583");
    return [x.toString(), y.toString(), "1"];
}

/** Fake BN254 G2 point. */
function fakeG2() {
    const r = () => (BigInt("0x" + rndHex(31)) % BigInt("21888242871839275222246405745257275088696311157297823662689037894645226208583")).toString();
    return [[r(), r()], [r(), r()], ["1", "0"]];
}

/** Fake Groth16 proof (same structure as real snarkjs output). */
function fakeProof() {
    return { pi_a: fakeG1(), pi_b: fakeG2(), pi_c: fakeG1(), protocol: "groth16", curve: "bn128" };
}

/** Truncate a long string for display. */
function trunc(s, len = 24) {
    s = String(s);
    return s.length > len ? s.slice(0, len) + "…" : s;
}

function fmtG1(arr) { return `(${trunc(arr[0])}, ${trunc(arr[1])})`; }
function fmtG2(arr) { return `([${trunc(arr[0][0])},…], [${trunc(arr[1][0])},…])`; }

function send(ws, obj) {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

// -------------------------------------------------------
// Express + WS
// -------------------------------------------------------
const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

app.use(express.static(path.join(__dirname, "public")));

// -------------------------------------------------------
// Init
// -------------------------------------------------------
async function init() {
    for (const f of [WASM, ZKEY, VK, INPUT]) {
        if (!fs.existsSync(f)) {
            console.error(`\n  Missing: ${f}`);
            console.error("  Run:  npm run setup  &&  npm run gen-input  first.\n");
            process.exit(1);
        }
    }
    console.log("Loading keys and building Poseidon + BN128 curve (takes ~5 s)…");
    vk         = JSON.parse(fs.readFileSync(VK));
    baseInput  = JSON.parse(fs.readFileSync(INPUT));
    poseidon   = await buildPoseidon();
    batchCurve = await buildBatchCurve();
    console.log("Ready. Open http://localhost:4000\n");
}

// -------------------------------------------------------
// WebSocket handler
// -------------------------------------------------------
wss.on("connection", ws => {
    sessions.set(ws, { identity: null, currentInput: null });

    send(ws, {
        type: "init",
        input: {
            merkleRoot : baseInput.merkleRoot,
            tCurrent   : baseInput.tCurrent,
            hMessage   : baseInput.hMessage,
            sid        : baseInput.sid,
            tStart     : baseInput.tStart,
            tEnd       : baseInput.tEnd,
            cap        : baseInput.cap,
        },
    });

    ws.on("message", async raw => {
        let msg;
        try { msg = JSON.parse(raw); } catch { return; }
        const handlers = {
            register : () => handleRegistration(ws, msg),
            acquire  : () => handleASTAcquisition(ws, msg),
            prove    : () => handleProve(ws, msg),
            batch    : () => handleBatch(ws, Math.min(Math.max(parseInt(msg.k) || 5, 1), 30)),
        };
        if (handlers[msg.cmd]) {
            handlers[msg.cmd]().catch(err => send(ws, { type: "error", message: err.message }));
        }
    });
});

// ═══════════════════════════════════════════════════════
// PHASE 1 — Vehicle Registration (simulated)
// ═══════════════════════════════════════════════════════
async function handleRegistration(ws, msg) {
    const session = sessions.get(ws);
    const vin = (msg.vin || "VIN-TH-2024-001").toUpperCase().trim();

    // Step 1: BN254 KeyGen
    send(ws, { type: "reg", step: "keygen_start" });
    await sleep(250);
    const sk = rndHex(32);                           // 256-bit scalar
    const pk = fakeG1();                             // G1 point (x, y, z=1)
    send(ws, { type: "reg", step: "keygen_done",
        sk : "0x" + sk.slice(0, 16) + "…",           // show first 8 bytes only
        pk : `(${trunc(pk[0])}, ${trunc(pk[1])})`,
    });

    // Step 2: Send (VIN, pk) to TA
    await sleep(180);
    send(ws, { type: "reg", step: "ta_send", vin, pkTrunc: trunc(pk[0]) });
    await sleep(420);   // simulated network RTT

    // Step 3: TA verifies VIN
    send(ws, { type: "reg", step: "ta_verify" });
    await sleep(300);

    // Step 4: TA generates nonce + signs H(pk || nonce)
    const nonce = rndHex(32);
    send(ws, { type: "reg", step: "ta_nonce", nonce: "0x" + nonce.slice(0, 16) + "…" });
    await sleep(200);

    // σ_i is a secp256k1-style ECDSA signature: (r, s)
    const sigR = rndHex(32);
    const sigS = rndHex(32);
    const pkTA = rndHex(33);   // compressed secp256k1 public key (33 bytes)
    send(ws, { type: "reg", step: "ta_sign",
        sigma  : { r: "0x" + sigR.slice(0, 16) + "…", s: "0x" + sigS.slice(0, 16) + "…" },
        pk_ta  : "0x" + pkTA.slice(0, 16) + "…",
    });
    await sleep(150);

    // Store in session
    session.identity = { vin, sk, pk, sigma: { r: sigR, s: sigS }, pk_ta: pkTA };

    send(ws, { type: "reg_complete",
        vin,
        pk_stored  : `(${trunc(pk[0])}, ${trunc(pk[1])})`,
        sig_stored : "0x" + sigR.slice(0, 10) + "…",
        pk_ta      : "0x" + pkTA.slice(0, 16) + "…",
    });
}

// ═══════════════════════════════════════════════════════
// PHASE 2 — AST Acquisition (hybrid: fake comms, real crypto)
// ═══════════════════════════════════════════════════════
async function handleASTAcquisition(ws, msg) {
    const session = sessions.get(ws);
    const F = poseidon.F;

    // Step 1: Connect to AIS
    send(ws, { type: "ast", step: "connect_start" });
    await sleep(450);

    // Step 2: Retrieve AIS certificate (simulated)
    const pkAIS  = rndHex(33);
    const sigTA  = rndHex(64);
    send(ws, { type: "ast", step: "cert_received",
        pk_ais   : "0x" + pkAIS.slice(0, 16) + "…",
        validity : "24 h",
        sig_ta   : "0x" + sigTA.slice(0, 16) + "…",
    });
    await sleep(250);

    // Step 3: ZKP of possession — π_σ  (simulated delay, fake proof)
    send(ws, { type: "ast", step: "zkp_start" });
    await sleep(900);   // realistic for a Groth16 prove on this device
    const piSigma = fakeProof();
    send(ws, { type: "ast", step: "zkp_done",
        pi_a : fmtG1(piSigma.pi_a),
        pi_b : fmtG2(piSigma.pi_b),
        pi_c : fmtG1(piSigma.pi_c),
        note : "Proves knowledge of σ_i without revealing sk_i or pk_i",
    });
    await sleep(200);

    // Step 4: AIS issues AST — REAL random values, will be used in Phase 3
    send(ws, { type: "ast", step: "ast_issued_start" });
    await sleep(300);

    const now    = BigInt(Math.floor(Date.now() / 1000));
    const sid    = BigInt("0x" + rndHex(8));
    const tStart = now - BigInt(300);            // AST was issued 5 min ago
    const tEnd   = tStart + BigInt(1800);        // 30-min validity window
    const cap    = BigInt(1);
    const r      = BigInt("0x" + rndHex(16));
    const tCur   = now;                          // tCurrent = actual wall-clock now

    send(ws, { type: "ast", step: "ast_issued",
        sid    : sid.toString(),
        tStart : tStart.toString(),
        tEnd   : tEnd.toString(),
        cap    : "1",
        r      : trunc(r.toString()),
    });
    await sleep(300);

    // Step 5: Build REAL Merkle tree with Poseidon (same as gen_input.js)
    send(ws, { type: "ast", step: "merkle_start" });
    await sleep(100);

    const DEPTH      = 8;
    const NUM_LEAVES = 1 << DEPTH;
    const leafIndex  = Math.floor(Math.random() * NUM_LEAVES);

    const ourLeaf = F.toObject(poseidon([sid, tStart, tEnd, cap, r]));
    const leaves  = [];
    for (let i = 0; i < NUM_LEAVES; i++) {
        leaves.push(i === leafIndex
            ? ourLeaf
            : F.toObject(poseidon([BigInt(i + 10000)])));
    }

    const tree = [leaves.slice()];
    let cur = leaves;
    while (cur.length > 1) {
        const next = [];
        for (let i = 0; i < cur.length; i += 2) {
            next.push(F.toObject(poseidon([cur[i], cur[i + 1]])));
        }
        tree.push(next);
        cur = next;
    }
    const merkleRoot = cur[0];

    const pathElements = [];
    const pathIndices  = [];
    let idx = leafIndex;
    for (let level = 0; level < DEPTH; level++) {
        const isRight = idx % 2;
        pathIndices.push(isRight);
        pathElements.push(tree[level][isRight ? idx - 1 : idx + 1]);
        idx = Math.floor(idx / 2);
    }

    // Compute intermediate node at each level along our path (for tree visualisation)
    // intermediates[0] = our leaf, intermediates[k] = ancestor at depth k, intermediates[8] = root
    const intermediates = [ourLeaf];
    for (let level = 0; level < DEPTH; level++) {
        const isRight  = pathIndices[level];
        const leftNode  = isRight ? pathElements[level] : intermediates[level];
        const rightNode = isRight ? intermediates[level] : pathElements[level];
        intermediates.push(F.toObject(poseidon([leftNode, rightNode])));
    }

    send(ws, { type: "ast", step: "merkle_done",
        root      : trunc(merkleRoot.toString()),
        depth     : DEPTH,
        leafIndex,
        numLeaves : NUM_LEAVES,
        leaf      : trunc(ourLeaf.toString()),
        path      : pathElements.slice(0, 3).map(x => trunc(x.toString())),
        treeViz   : {
            astFields    : {
                sid    : sid.toString(),
                tStart : tStart.toString(),
                tEnd   : tEnd.toString(),
                cap    : cap.toString(),
                r      : r.toString(),
            },
            leaf          : ourLeaf.toString(),
            pathElements  : pathElements.map(x => x.toString()),
            pathIndices,
            intermediates : intermediates.map(x => x.toString()),
        },
    });
    await sleep(300);

    // Step 6: AIS signs root
    const sigAIS = rndHex(64);
    send(ws, { type: "ast", step: "ais_signed",
        sig  : "0x" + sigAIS.slice(0, 20) + "…",
        root : trunc(merkleRoot.toString()),
    });
    await sleep(200);

    // Step 7: Offline precomputation (simulated cache fill)
    const N_CACHE = 8;
    send(ws, { type: "ast", step: "precomp_start", total: N_CACHE });
    for (let i = 0; i < N_CACHE; i++) {
        await sleep(160);
        send(ws, { type: "ast", step: "precomp_progress", done: i + 1, total: N_CACHE });
    }

    // Build real Phase-3-ready input object
    const hMessage = F.toObject(poseidon([BigInt(baseInput.message), tCur]));
    const newInput = {
        merkleRoot    : merkleRoot.toString(),
        tCurrent      : tCur.toString(),
        hMessage      : hMessage.toString(),
        sid           : sid.toString(),
        tStart        : tStart.toString(),
        tEnd          : tEnd.toString(),
        cap           : cap.toString(),
        r             : r.toString(),
        pathElements  : pathElements.map(x => x.toString()),
        pathIndices   : pathIndices.map(x => x.toString()),
        message       : baseInput.message,   // reuse default test BSM payload
    };
    session.currentInput = newInput;

    send(ws, { type: "ast_complete",
        merkleRoot : trunc(merkleRoot.toString()),
        tStart     : tStart.toString(),
        tEnd       : tEnd.toString(),
        tCurrent   : tCur.toString(),
        cacheSize  : N_CACHE,
        leafIndex,
        readyForPhase3 : true,
    });
}

// ═══════════════════════════════════════════════════════
// PHASE 3 — Online Proof Generation
// ═══════════════════════════════════════════════════════
async function handleProve(ws, msg) {
    const session = sessions.get(ws);
    // Use Phase-2 AST if available, otherwise fall back to test input
    const base = (session && session.currentInput) ? session.currentInput : baseInput;
    const F = poseidon.F;

    const msgBig   = msg.message ? BigInt(msg.message) : BigInt(base.message);
    const tCurrent = BigInt(base.tCurrent);
    const hMessage = F.toObject(poseidon([msgBig, tCurrent])).toString();

    const input = { ...base, message: msgBig.toString(), hMessage };

    send(ws, { type: "prove_inputs",
        pub  : { merkleRoot: input.merkleRoot, tCurrent: input.tCurrent, hMessage },
        priv : { sid: trunc(input.sid), tStart: input.tStart, tEnd: input.tEnd, cap: input.cap },
        bsm  : trunc(msgBig.toString(16), 24),
        fromPhase2 : !!(session && session.currentInput),
    });

    send(ws, { type: "step", step: "witness_start" });
    const t0 = performance.now();
    await snarkjs.wtns.calculate(input, WASM, { type: "mem" });
    const witnessMs = performance.now() - t0;
    send(ws, { type: "step", step: "witness_done", ms: +witnessMs.toFixed(2) });

    send(ws, { type: "step", step: "prove_start" });
    const t1 = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const proveMs = performance.now() - t1;

    const packetBytes = Buffer.byteLength(JSON.stringify({ proof, publicSignals }), "utf8");
    send(ws, { type: "step", step: "prove_done",
        ms            : +proveMs.toFixed(2),
        proof         : { pi_a: fmtG1(proof.pi_a), pi_b: fmtG2(proof.pi_b), pi_c: fmtG1(proof.pi_c) },
        publicSignals,
        packetBytes,
        proofRaw      : proof,
    });

    send(ws, { type: "step", step: "verify_start" });
    const t2 = performance.now();
    const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
    const verifyMs = performance.now() - t2;
    send(ws, { type: "step", step: "verify_done", ms: +verifyMs.toFixed(2), valid });

    send(ws, { type: "prove_complete",
        totalMs   : +(performance.now() - t0).toFixed(2),
        witnessMs : +witnessMs.toFixed(2),
        proveMs   : +proveMs.toFixed(2),
        verifyMs  : +verifyMs.toFixed(2),
    });
}

// ═══════════════════════════════════════════════════════
// PHASE 4 — Batch Verification
// ═══════════════════════════════════════════════════════
async function handleBatch(ws, k) {
    const session = sessions.get(ws);
    const base = (session && session.currentInput) ? session.currentInput : baseInput;
    const F = poseidon.F;

    send(ws, { type: "batch_start", k });

    const proofs  = [];
    const pubSigs = [];

    for (let i = 0; i < k; i++) {
        const msgBig   = BigInt("0xBEEF0000") + BigInt(i * 0x1111);
        const tCurrent = BigInt(base.tCurrent);
        const hMessage = F.toObject(poseidon([msgBig, tCurrent])).toString();
        const input    = { ...base, message: msgBig.toString(), hMessage };

        const t0 = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        const ms = performance.now() - t0;

        proofs.push(proof);
        pubSigs.push(publicSignals);
        send(ws, { type: "batch_proof_ready",
            index    : i + 1,
            k,
            ms       : +ms.toFixed(2),
            bsm      : "0x" + msgBig.toString(16).toUpperCase(),
            hMessage : trunc(hMessage),
        });
    }

    send(ws, { type: "step", step: "seq_verify_start", k });
    const t1 = performance.now();
    for (let i = 0; i < k; i++) await snarkjs.groth16.verify(vk, pubSigs[i], proofs[i]);
    const seqMs = performance.now() - t1;
    send(ws, { type: "step", step: "seq_verify_done", ms: +seqMs.toFixed(2), k });

    send(ws, { type: "step", step: "batch_verify_start", k });
    const t2 = performance.now();
    const result = await batchVerify(proofs, pubSigs, vk, batchCurve);
    const batchMs = performance.now() - t2;

    send(ws, { type: "batch_complete",
        k,
        seqMs         : +seqMs.toFixed(2),
        batchMs       : +batchMs.toFixed(2),
        speedup       : +(seqMs / batchMs).toFixed(2),
        valid         : result.valid,
        pairingsSeq   : 3 * k,
        pairingsBatch : k + 3,
        pairingsSaved : 3 * k - (k + 3),
    });
}

// -------------------------------------------------------
// Start
// -------------------------------------------------------
init().then(() => {
    server.listen(4000, () => console.log("Dashboard → http://localhost:4000"));
}).catch(err => { console.error(err); process.exit(1); });
