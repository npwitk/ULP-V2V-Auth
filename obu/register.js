/**
 * register.js — Vehicle Registration (Phase 1)
 *
 * Run ONCE on each RPi to register the vehicle with the TA.
 * Generates a BN254-compatible key pair, sends pubkey to TA,
 * and stores the credential in obu_data/identity.json.
 *
 * Run:  node obu/register.js --ta=http://MAC_IP:3001 --vin=VIN001
 */

const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");
const http   = require("http");

// -------------------------------------------------------
// CLI args
// -------------------------------------------------------
const TA_URL = process.argv.find(a => a.startsWith("--ta="))?.split("=")[1];
const VIN    = process.argv.find(a => a.startsWith("--vin="))?.split("=")[1];

if (!TA_URL || !VIN) {
    console.error("Usage: node obu/register.js --ta=http://MAC_IP:3001 --vin=VIN001");
    process.exit(1);
}

const DATA_DIR    = "obu_data";
const IDENTITY_PATH = path.join(DATA_DIR, "identity.json");

// -------------------------------------------------------
// Helpers
// -------------------------------------------------------
function httpPost(url, data) {
    return new Promise((resolve, reject) => {
        const { URL } = require("url");
        const parsed  = new URL(url);
        const body    = JSON.stringify(data);
        const req     = http.request({
            hostname: parsed.hostname,
            port:     parsed.port || 80,
            path:     parsed.pathname,
            method:   "POST",
            headers:  { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
        }, res => {
            let d = "";
            res.on("data", c => d += c);
            res.on("end", () => { try { resolve(JSON.parse(d)); } catch (e) { reject(new Error(d)); } });
        });
        req.on("error", reject);
        req.write(body);
        req.end();
    });
}

// -------------------------------------------------------
// Main
// -------------------------------------------------------
async function main() {
    console.log("=".repeat(52));
    console.log("  ULP-V2V-Auth  —  Vehicle Registration (Phase 1)");
    console.log(`  TA URL : ${TA_URL}`);
    console.log(`  VIN    : ${VIN}`);
    console.log("=".repeat(52));

    // Generate P-256 key pair (used to authenticate with AIS)
    console.log("\n[1] Generating EC P-256 key pair...");
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding:  { type: "spki",  format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "der" },
    });
    const pubkeyHex  = publicKey.toString("hex");
    const privkeyHex = privateKey.toString("hex");
    console.log(`  pubkey : ${pubkeyHex.slice(0, 24)}...`);

    // Register with TA
    console.log(`\n[2] Calling POST ${TA_URL}/register ...`);
    const t0  = performance.now();
    const res = await httpPost(`${TA_URL}/register`, { vin: VIN, pubkey: pubkeyHex });
    const rtt = performance.now() - t0;

    if (res.error) { console.error(`[TA] Error: ${res.error}`); process.exit(1); }

    console.log(`  RTT    : ${rtt.toFixed(1)} ms`);
    console.log(`  sigma  : ${res.sigma.slice(0, 24)}...`);
    console.log(`  nonce  : ${res.nonce.slice(0, 16)}...`);
    console.log(`  pk_ta  : ${res.pk_ta.slice(0, 24)}...`);

    // Save identity
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const identity = {
        vin:         VIN,
        pubkeyHex,
        privkeyHex,
        sigma:       res.sigma,
        nonce:       res.nonce,
        pk_ta:       res.pk_ta,
        registeredAt: new Date().toISOString(),
        registrationRtt_ms: parseFloat(rtt.toFixed(2)),
    };
    fs.writeFileSync(IDENTITY_PATH, JSON.stringify(identity, null, 2));

    console.log(`\n[3] Identity saved to ${IDENTITY_PATH}`);
    console.log("\n  Next step:  node obu/acquire_ast.js --ais=http://MAC_IP:3002");
}

main().catch(err => { console.error(err); process.exit(1); });
