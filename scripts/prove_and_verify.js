/**
 * prove_and_verify.js
 *
 * Runs a single full prove + verify cycle and reports:
 *   - Full proof generation time  (= "offline phase" cost)
 *   - Verification time           (= per-message receiver cost)
 *   - Proof size in bytes
 *
 * This is the "end-to-end correctness check" script.
 * For repeated latency benchmarks, use:  npm run bench
 *
 * Run:  node scripts/prove_and_verify.js
 */

const snarkjs = require("snarkjs");
const fs      = require("fs");
const path    = require("path");
const os      = require("os");

function detectHardware() {
    if (process.platform === "linux" && fs.existsSync("/proc/cpuinfo")) {
        const cpuinfo = fs.readFileSync("/proc/cpuinfo", "utf8");
        const modelMatch = cpuinfo.match(/^Model\s*:\s*(.+)$/m);
        if (modelMatch) return modelMatch[1].trim();
        const hwMatch = cpuinfo.match(/^Hardware\s*:\s*(.+)$/m);
        if (hwMatch) return `Linux/${hwMatch[1].trim()}`;
    }
    const cpu = os.cpus()[0]?.model ?? "Unknown CPU";
    const platform = process.platform === "darwin" ? "macOS" : os.platform();
    return `${platform} — ${cpu}`;
}

const WASM = path.join("build", "ulp_v2v_auth_js", "ulp_v2v_auth.wasm");
const ZKEY = path.join("keys",  "ulp_v2v_auth_final.zkey");
const VK   = path.join("keys",  "verification_key.json");
const IN   = path.join("build", "input.json");

async function main() {
    // Pre-flight checks
    for (const f of [WASM, ZKEY, VK, IN]) {
        if (!fs.existsSync(f)) {
            console.error(`Missing: ${f}`);
            console.error("Run  npm run setup  then  npm run gen-input  first.");
            process.exit(1);
        }
    }

    const input = JSON.parse(fs.readFileSync(IN));
    const vk    = JSON.parse(fs.readFileSync(VK));

    console.log("=".repeat(52));
    console.log("  ULP-V2V-Auth — Prove & Verify");
    console.log("=".repeat(52));

    // -------------------------------------------------------
    // OFFLINE PHASE:  full proof generation
    //   Includes: witness generation + full Groth16 prover
    //   In the paper this is amortised over the AST validity window;
    //   it runs once at parking / RSU contact, not per BSM.
    // -------------------------------------------------------
    console.log("\n[1] Full proof generation (offline phase)...");
    const t0 = performance.now();
    const { proof, publicSignals } =
        await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const offlineMs = performance.now() - t0;
    console.log(`    Time : ${offlineMs.toFixed(2)} ms`);

    // -------------------------------------------------------
    // ONLINE PHASE (receiver side): verification
    //   This runs on every receiving vehicle for every BSM.
    // -------------------------------------------------------
    console.log("\n[2] Proof verification (online phase, receiver)...");
    const t1 = performance.now();
    const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
    const verifyMs = performance.now() - t1;
    console.log(`    Time  : ${verifyMs.toFixed(2)} ms`);
    console.log(`    Valid : ${valid ? "✓ YES" : "✗ NO"}`);

    if (!valid) {
        console.error("\nProof verification FAILED — check circuit inputs.");
        process.exit(1);
    }

    // -------------------------------------------------------
    // Proof size analysis
    // -------------------------------------------------------
    const proofJson  = JSON.stringify(proof);
    const proofBytes = Buffer.byteLength(proofJson, "utf8");
    // A Groth16 proof on BN254 = 3 curve points = 2*32 + 2*2*32 + 2*32 = 256 bytes (uncompressed)
    // or ~128 bytes compressed. The JSON is larger due to decimal encoding.
    console.log("\n[3] Proof size");
    console.log(`    JSON (decimal encoded) : ${proofBytes} bytes`);
    console.log(`    Binary (BN254 points)  : ~128 bytes  (3 compressed curve points)`);
    console.log(`    Public signals         : ${publicSignals.length} field elements`);

    // -------------------------------------------------------
    // Summary for paper
    // -------------------------------------------------------
    console.log("\n" + "=".repeat(52));
    console.log("  Summary");
    console.log("=".repeat(52));
    console.log(`  Full prove  : ${offlineMs.toFixed(1)} ms  (offline, amortised)`);
    console.log(`  Verify      : ${verifyMs.toFixed(1)} ms  (online, per-BSM)`);
    console.log(`  Proof size  : ~128 bytes`);
    console.log("=".repeat(52));
    const hw = detectHardware();
    console.log(`\nHardware: ${hw}`);
    if (!hw.toLowerCase().includes("raspberry")) {
        console.log("Multiply by ~6–8x for Raspberry Pi 4 (ARM Cortex-A72 @ 1.8 GHz).");
    }

    // Save proof and public signals for batch benchmark reuse
    fs.mkdirSync("build", { recursive: true });
    fs.writeFileSync(path.join("build", "proof.json"),  JSON.stringify(proof, null, 2));
    fs.writeFileSync(path.join("build", "public.json"), JSON.stringify(publicSignals, null, 2));
    console.log("\nProof saved to build/proof.json");
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
