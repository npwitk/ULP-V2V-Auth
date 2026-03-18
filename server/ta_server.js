/**
 * ta_server.js — Trusted Authority (TA) Server
 *
 * Phase 1: Vehicle Registration.
 * Runs on Mac. Vehicles (RPi OBUs) call POST /register to receive
 * a TA signature (sigma_i) over their public key.
 *
 * Endpoints:
 *   POST /register  { vin, pubkey }  →  { sigma, nonce, pk_ta }
 *   GET  /pk                         →  { pk_ta }
 *   GET  /vehicles                   →  { list of registered VINs }
 *
 * Run:  node server/ta_server.js [--port=3001]
 */

const express = require("express");
const crypto  = require("crypto");
const fs      = require("fs");
const path    = require("path");

const PORT = parseInt(process.argv.find(a => a.startsWith("--port="))?.split("=")[1] ?? "3001");

// -------------------------------------------------------
// TA Key pair — persisted across restarts
// -------------------------------------------------------
const KEYS_PATH = path.join("server_data", "ta_keys.json");
fs.mkdirSync("server_data", { recursive: true });

let taPrivKey, taPubKeyHex;
if (fs.existsSync(KEYS_PATH)) {
    const saved = JSON.parse(fs.readFileSync(KEYS_PATH));
    taPrivKey   = crypto.createPrivateKey({ key: Buffer.from(saved.privDer, "hex"), format: "der", type: "pkcs8" });
    taPubKeyHex = saved.pubDer;
    console.log("[TA] Loaded existing key pair.");
} else {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding:  { type: "spki",  format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "der" },
    });
    taPrivKey   = crypto.createPrivateKey({ key: privateKey, format: "der", type: "pkcs8" });
    taPubKeyHex = publicKey.toString("hex");
    fs.writeFileSync(KEYS_PATH, JSON.stringify({ privDer: privateKey.toString("hex"), pubDer: taPubKeyHex }));
    console.log("[TA] Generated new key pair.");
}

// -------------------------------------------------------
// Allowed VINs (whitelist — expand as needed)
// -------------------------------------------------------
const ALLOWED_VINS = new Set([
    "VIN001", "VIN002", "VIN003", "VIN004", "VIN005",
]);

// In-memory vehicle registry { vin → { pubkey, nonce, sigma, registeredAt } }
const registry = new Map();

// -------------------------------------------------------
// Express routes
// -------------------------------------------------------
const app = express();
app.use(express.json());

// Return TA public key (AIS fetches this at startup)
app.get("/pk", (req, res) => {
    res.json({ pk_ta: taPubKeyHex });
});

// Vehicle registration
app.post("/register", (req, res) => {
    const { vin, pubkey } = req.body;
    if (!vin || !pubkey)         return res.status(400).json({ error: "Missing vin or pubkey" });
    if (!ALLOWED_VINS.has(vin)) return res.status(403).json({ error: "VIN not in allowlist" });

    const nonce   = crypto.randomBytes(32).toString("hex");
    const payload = pubkey + nonce;

    const signer  = crypto.createSign("SHA256");
    signer.update(payload);
    const sigma   = signer.sign(taPrivKey).toString("hex");

    registry.set(vin, { pubkey, nonce, sigma, registeredAt: new Date().toISOString() });
    console.log(`[TA] Registered: ${vin}`);

    res.json({ sigma, nonce, pk_ta: taPubKeyHex });
});

// Inspection endpoint
app.get("/vehicles", (req, res) => {
    const list = {};
    for (const [vin, d] of registry)
        list[vin] = { pubkey: d.pubkey.slice(0, 20) + "...", registeredAt: d.registeredAt };
    res.json(list);
});

app.listen(PORT, "0.0.0.0", () => {
    console.log("=".repeat(56));
    console.log(`  ULP-V2V-Auth  —  Trusted Authority Server`);
    console.log(`  Listening on  http://0.0.0.0:${PORT}`);
    console.log(`  pk_ta         ${taPubKeyHex.slice(0, 24)}...`);
    console.log("=".repeat(56));
    console.log("  POST /register   { vin, pubkey }");
    console.log("  GET  /pk");
});
