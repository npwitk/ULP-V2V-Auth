pragma circom 2.0.0;

// Imports from circomlib (installed via npm)
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/switcher.circom";

// -------------------------------------------------------
// MerklePathVerifier
//   Verifies that `leaf` is included in a Merkle tree
//   with root `root` using Poseidon hashing.
//   `depth` = tree depth (8 for Mac test, 16 for full)
// -------------------------------------------------------
template MerklePathVerifier(depth) {
    signal input leaf;
    signal input pathElements[depth];   // sibling hashes along the path
    signal input pathIndices[depth];    // 0 = current node is left, 1 = right

    signal output root;

    component hashers[depth];
    component switchers[depth];
    signal levelHashes[depth + 1];

    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // Switcher: if pathIndices[i]=0 → (current, sibling); if 1 → (sibling, current)
        switchers[i] = Switcher();
        switchers[i].L   <== levelHashes[i];
        switchers[i].R   <== pathElements[i];
        switchers[i].sel <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[depth];
}

// -------------------------------------------------------
// ULP_V2V_Auth  — the main circuit
//
// Public inputs  (known to verifier):
//   merkleRoot  — current Merkle root R
//   tCurrent    — timestamp of the safety message
//   hMessage    — Poseidon(message, tCurrent)
//
// Private witness (known only to prover):
//   sid, tStart, tEnd, cap, r  — AST fields
//   pathElements[depth]         — Merkle siblings
//   pathIndices[depth]          — path direction bits
//   message                    — raw BSM content
//
// Proved statement:
//   (1) leaf = Poseidon(sid, tStart, tEnd, cap, r)
//   (2) MerkleVerify(leaf, path) == merkleRoot
//   (3) tStart <= tCurrent <= tEnd
//   (4) hMessage == Poseidon(message, tCurrent)
// -------------------------------------------------------
template ULP_V2V_Auth(depth) {

    // === Public inputs ===
    signal input merkleRoot;
    signal input tCurrent;
    signal input hMessage;

    // === Private witness ===
    signal input sid;
    signal input tStart;
    signal input tEnd;
    signal input cap;
    signal input r;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input message;

    // -------------------------------------------------------
    // Constraint 1: Compute AST leaf
    // leaf = Poseidon(sid, tStart, tEnd, cap, r)
    // -------------------------------------------------------
    component leafHasher = Poseidon(5);
    leafHasher.inputs[0] <== sid;
    leafHasher.inputs[1] <== tStart;
    leafHasher.inputs[2] <== tEnd;
    leafHasher.inputs[3] <== cap;
    leafHasher.inputs[4] <== r;

    // -------------------------------------------------------
    // Constraint 2: Merkle path verification
    // -------------------------------------------------------
    component merkleVerifier = MerklePathVerifier(depth);
    merkleVerifier.leaf <== leafHasher.out;
    for (var i = 0; i < depth; i++) {
        merkleVerifier.pathElements[i] <== pathElements[i];
        merkleVerifier.pathIndices[i]  <== pathIndices[i];
    }
    merkleVerifier.root === merkleRoot;

    // -------------------------------------------------------
    // Constraint 3: Timestamp validity window
    // tStart <= tCurrent  AND  tCurrent <= tEnd
    // Using 32-bit comparators (handles timestamps up to year 2106)
    // -------------------------------------------------------
    component leqStart = LessEqThan(32);
    leqStart.in[0] <== tStart;
    leqStart.in[1] <== tCurrent;
    leqStart.out === 1;

    component leqEnd = LessEqThan(32);
    leqEnd.in[0] <== tCurrent;
    leqEnd.in[1] <== tEnd;
    leqEnd.out === 1;

    // -------------------------------------------------------
    // Constraint 4: Message hash binding
    // hMessage = Poseidon(message, tCurrent)
    // -------------------------------------------------------
    component msgHasher = Poseidon(2);
    msgHasher.inputs[0] <== message;
    msgHasher.inputs[1] <== tCurrent;
    msgHasher.out === hMessage;
}

// depth=16 → 65536 leaves, ~9000-10000 constraints, requires pot14
component main {public [merkleRoot, tCurrent, hMessage]} = ULP_V2V_Auth(16);
