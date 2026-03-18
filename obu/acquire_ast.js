/**
 * acquire_ast.js — AST Acquisition (Phase 2)
 *
 * Contacts the AIS with the vehicle's TA-signed credential, receives
 * an Anonymous Session Token (AST) with its Merkle path, and writes
 * build/input.json so that npm run bench / bench-rapid work immediately.
 *
 * Run:  node obu/acquire_ast.js --ais=http://MAC_IP:3002
 */

const fs   = require("fs");
const path = require("path");
const http = require("http");

// -------------------------------------------------------
// CLI args
// -------------------------------------------------------
const AIS_URL = process.argv.find(a => a.startsWith("--ais="))?.split("=")[1];
if (!AIS_URL) {
    console.error("Usage: node obu/acquire_ast.js --ais=http://MAC_IP:3002");
    process.exit(1);
}

const IDENTITY_PATH = path.join("obu_data", "identity.json");
const AST_PATH      = path.join("obu_data", "ast.json");
const INPUT_PATH    = path.join("build",    "input.json");

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
    console.log("  ULP-V2V-Auth  —  AST Acquisition (Phase 2)");
    console.log(`  AIS URL : ${AIS_URL}`);
    console.log("=".repeat(52));

    // Load identity
    if (!fs.existsSync(IDENTITY_PATH)) {
        console.error(`Identity not found at ${IDENTITY_PATH}`);
        console.error("Run:  node obu/register.js --ta=http://MAC_IP:3001 --vin=VIN001");
        process.exit(1);
    }
    const identity = JSON.parse(fs.readFileSync(IDENTITY_PATH));
    console.log(`\n[1] Loaded identity: VIN=${identity.vin}`);

    // Request AST from AIS
    console.log(`\n[2] Calling POST ${AIS_URL}/acquire ...`);
    const t0  = performance.now();
    const res = await httpPost(`${AIS_URL}/acquire`, {
        vin:    identity.vin,
        pubkey: identity.pubkeyHex,
        sigma:  identity.sigma,
        nonce:  identity.nonce,
    });
    const rtt = performance.now() - t0;

    if (res.error) { console.error(`[AIS] Error: ${res.error}`); process.exit(1); }

    console.log(`  RTT              : ${rtt.toFixed(1)} ms`);
    console.log(`  leafIndex        : ${res.leafIndex}`);
    console.log(`  merkleRoot       : ${res.merkleRoot.slice(0, 20)}...`);
    console.log(`  AST tStart       : ${res.ast.tStart}`);
    console.log(`  AST tEnd         : ${res.ast.tEnd}`);

    // Save raw AST response
    fs.mkdirSync("obu_data", { recursive: true });
    fs.writeFileSync(AST_PATH, JSON.stringify({ ...res, acquisitionRtt_ms: parseFloat(rtt.toFixed(2)), timestamp: new Date().toISOString() }, null, 2));

    // -------------------------------------------------------
    // Build build/input.json for the ZKP circuit
    // Matches format of scripts/gen_input.js exactly
    // -------------------------------------------------------
    const tCurrent = BigInt(Math.floor(Date.now() / 1000));

    // Ensure tCurrent is within [tStart, tEnd]
    const tStart = BigInt(res.ast.tStart);
    const tEnd   = BigInt(res.ast.tEnd);
    const tUse   = tCurrent < tStart ? tStart :
                   tCurrent > tEnd   ? tEnd   : tCurrent;

    // Representative BSM message (matches prover scripts)
    const MESSAGE = BigInt("0xBEEF0001CAFE0002DEAD0003BABE0004");

    // hMessage is computed by the circuit verifier too — include it as a placeholder
    // (the bench scripts compute the actual hMessage at prove time)
    const input = {
        // Public inputs
        merkleRoot  : res.merkleRoot,
        tCurrent    : tUse.toString(),
        hMessage    : "0",   // placeholder — overwritten at prove time by bench scripts

        // Private witness
        sid          : res.ast.sid,
        tStart       : res.ast.tStart,
        tEnd         : res.ast.tEnd,
        cap          : res.ast.cap,
        r            : res.ast.r,
        pathElements : res.merklePathElements,
        pathIndices  : res.merklePathIndices,
        message      : MESSAGE.toString(),
    };

    fs.mkdirSync("build", { recursive: true });
    fs.writeFileSync(INPUT_PATH, JSON.stringify(input, null, 2));

    console.log(`\n[3] AST saved to        ${AST_PATH}`);
    console.log(`[4] Circuit input saved to ${INPUT_PATH}`);
    console.log(`    (hMessage=0 placeholder — bench scripts set the real value)`);
    console.log(`\n  AST acquisition RTT: ${rtt.toFixed(1)} ms`);
    console.log("\n  Next step:  node obu/bench_e2e.js --ais=http://MAC_IP:3002");
    console.log("  Or run benchmarks:  npm run bench && npm run bench-rapid");
}

main().catch(err => { console.error(err); process.exit(1); });
