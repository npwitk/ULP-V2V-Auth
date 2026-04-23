pragma circom 2.0.0;

// Imports from circomlib (installed via npm)
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/switcher.circom";

// -------------------------------------------------------
// MerklePathVerifier
//   Verifies that `leaf` is included in a Merkle tree
//   with root `root` using Poseidon hashing.
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
// ULP_V2V_Auth — One-Time-Key Variant (highway deployment)
//
// Public inputs  (known to verifier, committed by Groth16):
//   merkleRoot  — current Merkle root R
//   tCurrent    — predicted timestamp for this slot
//   pkOt        — one-time ECDSA-P256 public key (x-coordinate)
//
// Private witness (known only to prover):
//   sid, tStart, tEnd, cap, r  — AST fields
//   pathElements[depth]         — Merkle siblings
//   pathIndices[depth]          — path direction bits
//
// Proved statement:
//   (1) leaf = Poseidon(sid, tStart, tEnd, cap, r)
//   (2) MerkleVerify(leaf, path) == merkleRoot
//   (3) tStart <= tCurrent <= tEnd
//   (4) pkOt is committed as a public input (binding via Groth16 IC vector)
//
// Message binding is handled outside the circuit: the prover signs
// (m || t_current) with sk_ot, the verifier checks ECDSA under pk_ot.
// This is the one-time-key design: no message content enters the circuit,
// so every cached proof slot is usable for any BSM content.
//
// Deployment: depth=8 → 256 simultaneous ASTs, sufficient for highway
// segments (AIS zone ~1–2 km, dense 3-lane = ≤200 vehicles).
// -------------------------------------------------------
template ULP_V2V_Auth(depth) {

    // === Public inputs ===
    signal input merkleRoot;   // Merkle root R (epoch-bound)
    signal input tCurrent;     // predicted slot timestamp
    signal input pkOt;         // one-time public key x-coordinate (P-256)

    // === Private witness ===
    signal input sid;
    signal input tStart;
    signal input tEnd;
    signal input cap;
    signal input r;
    signal input pathElements[depth];
    signal input pathIndices[depth];

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
    // Constraint 4: pkOt binding anchor
    // pkOt is a public input; Groth16's IC vector commitment ensures
    // this proof is only valid for the specific pkOt used at generation.
    // One linear constraint anchors pkOt in the R1CS so Circom does not
    // treat it as unused.
    // -------------------------------------------------------
    signal pkOtRef;
    pkOtRef <== pkOt;
}

// depth=8 → 256 leaves, ~5800 constraints (est.), requires pot13 (2^13=8192)
// Sufficient for highway deployment: dense 3-lane, 1-2 km AIS zone ≤ 200 vehicles.
// For metro-scale deployment, increase to depth=16 (65536 leaves, ~9100 constraints).
component main {public [merkleRoot, tCurrent, pkOt]} = ULP_V2V_Auth(8);
