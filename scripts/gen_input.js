/**
 * gen_input.js
 *
 * Builds a test Merkle tree of AST leaves using Poseidon hashing,
 * generates a valid Merkle inclusion proof for one leaf, computes
 * the public inputs, and writes everything to build/input.json.
 *
 * Run:  node scripts/gen_input.js
 */

const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const path = require("path");

// -------------------------------------------------------
// Configuration
// -------------------------------------------------------
const DEPTH      = 16;          // must match circuit parameter
const NUM_LEAVES = 1 << DEPTH;  // 65536
const LEAF_INDEX = 3;           // which leaf is "our" AST

// -------------------------------------------------------
// Test AST values (in a real system these come from the AIS)
// -------------------------------------------------------
const AST = {
    sid    : BigInt("0x1A2B3C4D5E6F7A8B"),   // random session ID
    tStart : BigInt(1700000000),               // 2023-11-14 22:13:20 UTC
    tEnd   : BigInt(1700002800),               // +46 min (>= 2 epochs)
    cap    : BigInt(1),                        // capability bitmask
    r      : BigInt("0xDEADBEEFCAFEBABE1234"), // random blinding factor
};

// Current timestamp within [tStart, tEnd]
const T_CURRENT = BigInt(1700001400); // +23 min

// Simulated BSM payload (in practice: hash of full BSM fields)
const MESSAGE = BigInt("0xBEEF0001CAFE0002DEAD0003BABE0004");


async function main() {
    console.log("Building Poseidon hasher...");
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Helper: hash array of BigInts → BigInt
    const hash = (...args) => F.toObject(poseidon(args));

    // -------------------------------------------------------
    // 1. Compute our AST leaf
    // -------------------------------------------------------
    const ourLeaf = hash(AST.sid, AST.tStart, AST.tEnd, AST.cap, AST.r);
    console.log(`AST leaf (index ${LEAF_INDEX}): ${ourLeaf.toString().slice(0,20)}...`);

    // -------------------------------------------------------
    // 2. Build the full Merkle tree (level 0 = leaves)
    // -------------------------------------------------------
    // Populate all leaves — others are Poseidon(index) as placeholders
    const leaves = [];
    for (let i = 0; i < NUM_LEAVES; i++) {
        leaves.push(i === LEAF_INDEX
            ? ourLeaf
            : hash(BigInt(i + 10000)));    // deterministic placeholder
    }

    // Build tree level by level upward
    const tree = [leaves.slice()];
    let currentLevel = leaves;
    while (currentLevel.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            nextLevel.push(hash(currentLevel[i], currentLevel[i + 1]));
        }
        tree.push(nextLevel);
        currentLevel = nextLevel;
    }
    const merkleRoot = currentLevel[0];
    console.log(`Merkle root: ${merkleRoot.toString().slice(0,20)}...`);

    // -------------------------------------------------------
    // 3. Extract Merkle path for LEAF_INDEX
    // -------------------------------------------------------
    const pathElements = [];
    const pathIndices  = [];
    let idx = LEAF_INDEX;
    for (let level = 0; level < DEPTH; level++) {
        const isRight  = idx % 2;             // 1 if current node is right child
        const sibIdx   = isRight ? idx - 1 : idx + 1;
        pathIndices.push(isRight);
        pathElements.push(tree[level][sibIdx]);
        idx = Math.floor(idx / 2);
    }

    // -------------------------------------------------------
    // 4. Compute public inputs
    // -------------------------------------------------------
    const hMessage = hash(MESSAGE, T_CURRENT);
    console.log(`h_m = Poseidon(msg, t): ${hMessage.toString().slice(0,20)}...`);

    // -------------------------------------------------------
    // 5. Write input.json
    // -------------------------------------------------------
    const input = {
        // --- Public inputs (shared with verifier) ---
        merkleRoot : merkleRoot.toString(),
        tCurrent   : T_CURRENT.toString(),
        hMessage   : hMessage.toString(),

        // --- Private witness (stays with prover) ---
        sid          : AST.sid.toString(),
        tStart       : AST.tStart.toString(),
        tEnd         : AST.tEnd.toString(),
        cap          : AST.cap.toString(),
        r            : AST.r.toString(),
        pathElements : pathElements.map(x => x.toString()),
        pathIndices  : pathIndices.map(x => x.toString()),
        message      : MESSAGE.toString(),
    };

    const outPath = path.join("build", "input.json");
    fs.mkdirSync("build", { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(input, null, 2));
    console.log(`\nInput written to ${outPath}`);

    // Also save tree metadata for inspection / debugging
    const metaPath = path.join("build", "tree_meta.json");
    fs.writeFileSync(metaPath, JSON.stringify({
        depth      : DEPTH,
        numLeaves  : NUM_LEAVES,
        leafIndex  : LEAF_INDEX,
        merkleRoot : merkleRoot.toString(),
        pathLength : pathElements.length,
    }, null, 2));
    console.log(`Tree metadata written to ${metaPath}`);
    console.log("\nReady to prove! Run:  npm run prove");
}

main().catch(err => {
    console.error("Error:", err);
    process.exit(1);
});
