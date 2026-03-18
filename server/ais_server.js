/**
 * ais_server.js — AST Issuing Service (AIS) Server
 *
 * Phase 2: AST Acquisition.
 * Runs on Mac. Vehicles present their TA-signed credential and receive
 * an Anonymous Session Token (AST) with a Merkle inclusion proof.
 *
 * The Merkle tree uses Poseidon-2 hashing, matching the ZKP circuit.
 *
 * Endpoints:
 *   POST /acquire  { vin, pubkey, sigma, nonce }  →  { ast, merkleRoot,
 *                   merklePathElements, merklePathIndices, sigAis, leafIndex }
 *   GET  /root                                    →  { merkleRoot, epoch }
 *   GET  /pk                                      →  { pk_ais }
 *
 * Run:  node server/ais_server.js [--port=3002] [--ta=http://MAC_IP:3001]
 */

const express = require("express");
const crypto  = require("crypto");
const fs      = require("fs");
const path    = require("path");
const http    = require("http");
const { buildPoseidon } = require("circomlibjs");

const PORT   = parseInt(process.argv.find(a => a.startsWith("--port="))?.split("=")[1] ?? "3002");
const TA_URL = process.argv.find(a => a.startsWith("--ta="))?.split("=")[1] ?? "http://127.0.0.1:3001";

// Circuit parameters — must match ulp_v2v_auth.circom
const DEPTH      = 8;
const NUM_LEAVES = 1 << DEPTH;   // 256

// AST validity window: 30-minute session spanning 2 epochs
const AST_DURATION_SEC = 1800;

// -------------------------------------------------------
// Poseidon Merkle Tree
// -------------------------------------------------------
class PoseidonMerkleTree {
    constructor(poseidon) {
        this.poseidon  = poseidon;
        this.F         = poseidon.F;
        this.depth     = DEPTH;
        this.size      = NUM_LEAVES;
        this.nextIndex = 0;
        // Initialise all leaves to Poseidon(index+10000) — matches gen_input.js placeholder
        this.leaves = [];
        for (let i = 0; i < this.size; i++)
            this.leaves.push(this._hash(BigInt(i + 10000)));
        this._buildTree();
    }

    _hash(...args) {
        return this.F.toObject(this.poseidon(args));
    }

    _buildTree() {
        this.tree = [this.leaves.slice()];
        let level = this.leaves.slice();
        while (level.length > 1) {
            const next = [];
            for (let i = 0; i < level.length; i += 2)
                next.push(this._hash(level[i], level[i + 1]));
            this.tree.push(next);
            level = next;
        }
        this.root = level[0];
    }

    insertLeaf(leaf) {
        if (this.nextIndex >= this.size) throw new Error("Merkle tree full");
        const idx = this.nextIndex++;
        this.leaves[idx] = leaf;
        this._buildTree();
        return idx;
    }

    getPath(idx) {
        const elements = [], indices = [];
        let i = idx;
        for (let level = 0; level < this.depth; level++) {
            const isRight = i % 2;
            indices.push(isRight);
            elements.push(this.tree[level][isRight ? i - 1 : i + 1]);
            i = Math.floor(i / 2);
        }
        return { elements, indices };
    }

    leafHash(sid, tStart, tEnd, cap, r) {
        return this._hash(sid, tStart, tEnd, cap, r);
    }
}

// -------------------------------------------------------
// AIS Key pair
// -------------------------------------------------------
const KEYS_PATH = path.join("server_data", "ais_keys.json");
fs.mkdirSync("server_data", { recursive: true });

let aisPrivKey, aisPubKeyHex;
if (fs.existsSync(KEYS_PATH)) {
    const saved = JSON.parse(fs.readFileSync(KEYS_PATH));
    aisPrivKey   = crypto.createPrivateKey({ key: Buffer.from(saved.privDer, "hex"), format: "der", type: "pkcs8" });
    aisPubKeyHex = saved.pubDer;
    console.log("[AIS] Loaded existing AIS key pair.");
} else {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding:  { type: "spki",  format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "der" },
    });
    aisPrivKey   = crypto.createPrivateKey({ key: privateKey, format: "der", type: "pkcs8" });
    aisPubKeyHex = publicKey.toString("hex");
    fs.writeFileSync(KEYS_PATH, JSON.stringify({ privDer: privateKey.toString("hex"), pubDer: aisPubKeyHex }));
    console.log("[AIS] Generated new AIS key pair.");
}

// -------------------------------------------------------
// Helpers
// -------------------------------------------------------
function httpGet(url) {
    return new Promise((resolve, reject) => {
        http.get(url, res => {
            let data = "";
            res.on("data", c => data += c);
            res.on("end", () => { try { resolve(JSON.parse(data)); } catch (e) { reject(e); } });
        }).on("error", reject);
    });
}

function verifyTaSig(pk_ta_hex, pubkey, nonce, sigma_hex) {
    try {
        const pubKey  = crypto.createPublicKey({ key: Buffer.from(pk_ta_hex, "hex"), format: "der", type: "spki" });
        const payload = pubkey + nonce;
        const v       = crypto.createVerify("SHA256");
        v.update(payload);
        return v.verify(pubKey, Buffer.from(sigma_hex, "hex"));
    } catch { return false; }
}

// -------------------------------------------------------
// Startup: fetch TA public key, initialise Merkle tree
// -------------------------------------------------------
async function startServer() {
    // 1. Fetch pk_ta from TA
    console.log(`[AIS] Fetching TA public key from ${TA_URL}/pk ...`);
    let pk_ta_hex;
    try {
        const res = await httpGet(`${TA_URL}/pk`);
        pk_ta_hex = res.pk_ta;
        console.log(`[AIS] pk_ta: ${pk_ta_hex.slice(0, 24)}...`);
    } catch (e) {
        console.error(`[AIS] Cannot reach TA at ${TA_URL} — start ta_server.js first.`);
        process.exit(1);
    }

    // 2. Initialise Poseidon Merkle tree
    console.log("[AIS] Building Poseidon Merkle tree (depth=8, 256 leaves)...");
    const poseidon = await buildPoseidon();
    const tree     = new PoseidonMerkleTree(poseidon);
    console.log(`[AIS] Initial root: ${tree.root.toString().slice(0, 20)}...`);

    let epoch = 0;

    // -------------------------------------------------------
    // Express routes
    // -------------------------------------------------------
    const app = express();
    app.use(express.json());

    app.get("/pk", (req, res) => res.json({ pk_ais: aisPubKeyHex }));

    app.get("/root", (req, res) => res.json({
        merkleRoot: tree.root.toString(),
        epoch,
    }));

    app.post("/acquire", (req, res) => {
        const { vin, pubkey, sigma, nonce } = req.body;
        if (!vin || !pubkey || !sigma || !nonce)
            return res.status(400).json({ error: "Missing fields" });

        // Verify TA signature on vehicle's public key
        if (!verifyTaSig(pk_ta_hex, pubkey, nonce, sigma))
            return res.status(403).json({ error: "Invalid TA credential" });

        // Generate AST fields
        const F        = poseidon.F;
        const sid      = BigInt("0x" + crypto.randomBytes(8).toString("hex"));
        const tStart   = BigInt(Math.floor(Date.now() / 1000));
        const tEnd     = tStart + BigInt(AST_DURATION_SEC);
        const cap      = BigInt(1);
        const r        = BigInt("0x" + crypto.randomBytes(16).toString("hex")) %
                         BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

        // Insert leaf into Merkle tree
        const leaf     = tree.leafHash(sid, tStart, tEnd, cap, r);
        const leafIdx  = tree.insertLeaf(leaf);
        const { elements, indices } = tree.getPath(leafIdx);

        // AIS signature: sign SHA256(merkleRoot || leafIndex)
        const sigPayload = tree.root.toString() + leafIdx.toString();
        const signer     = crypto.createSign("SHA256");
        signer.update(sigPayload);
        const sigAis     = signer.sign(aisPrivKey).toString("hex");

        console.log(`[AIS] Issued AST to ${vin} — leafIdx=${leafIdx} root=${tree.root.toString().slice(0, 12)}...`);

        res.json({
            ast: {
                sid:    sid.toString(),
                tStart: tStart.toString(),
                tEnd:   tEnd.toString(),
                cap:    cap.toString(),
                r:      r.toString(),
            },
            merkleRoot:          tree.root.toString(),
            merklePathElements:  elements.map(x => x.toString()),
            merklePathIndices:   indices.map(x => x.toString()),
            leafIndex:           leafIdx,
            sigAis,
            pk_ais:              aisPubKeyHex,
            epoch,
        });
    });

    app.listen(PORT, "0.0.0.0", () => {
        console.log("=".repeat(56));
        console.log(`  ULP-V2V-Auth  —  AST Issuing Service`);
        console.log(`  Listening on  http://0.0.0.0:${PORT}`);
        console.log(`  TA URL        ${TA_URL}`);
        console.log("=".repeat(56));
        console.log("  POST /acquire  { vin, pubkey, sigma, nonce }");
        console.log("  GET  /root");
    });
}

startServer().catch(err => { console.error(err); process.exit(1); });
