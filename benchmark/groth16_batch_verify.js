/**
 * groth16_batch_verify.js
 *
 * TRUE Groth16 batch verification using ffjavascript curve primitives.
 *
 * snarkjs.groth16.verify() calls curve.pairingEq() once per proof,
 * meaning k proofs = k final exponentiations (the expensive part).
 *
 * Batch verification passes all k+3 pairing pairs into a SINGLE
 * curve.pairingEq() call → k+3 Miller loops + 1 final exponentiation.
 * For k individual verifications: 3k Miller loops + k final exponentiations.
 * (treating e(α,β) as precomputed; it folds into the aggregated alpha term)
 *
 * The final exponentiation is ~70% of pairing cost, so the saving is real
 * and measurable — not just theoretical.
 *
 * Algorithm (Bellare et al. 1998, applied to Groth16 structure):
 *
 * Individual check for proof j:
 *   e(A_j, B_j) = e(α, β) · e(L_j, γ) · e(C_j, δ)
 *
 * Batch check (sample random ρ_j, multiply all equations):
 *   ∏_j e(ρ_j·A_j, B_j) · e(-∑ρ_j·α, β) · e(-∑ρ_j·L_j, γ) · e(-∑ρ_j·C_j, δ) = 1
 *
 * This is k+3 pairings in one pairingEq() → one final exponentiation.
 */

const { getCurveFromName, utils } = require("ffjavascript");
const { unstringifyBigInts } = utils;

// BN128 scalar field order
const FIELD_R = BigInt(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

/**
 * Generate a random scalar in [1, FIELD_R-1]
 * Uses crypto.getRandomValues for proper randomness.
 */
function randomScalar() {
    const bytes = new Uint8Array(32);
    // Node.js crypto
    require("crypto").randomFillSync(bytes);
    let val = BigInt(0);
    for (const b of bytes) val = (val << BigInt(8)) | BigInt(b);
    return (val % (FIELD_R - BigInt(1))) + BigInt(1);
}

/**
 * Compute the linear combination point L_j:
 *   L_j = IC[0] + ∑_i publicSignals[i] · IC[i+1]
 * This is the "input wire" commitment in Groth16.
 */
function computeL(publicSignals, vkIC, G1) {
    let L = G1.fromObject(vkIC[0]);
    for (let i = 0; i < publicSignals.length; i++) {
        const scalar = BigInt(publicSignals[i]);
        const term   = G1.timesScalar(G1.fromObject(vkIC[i + 1]), scalar);
        L = G1.add(L, term);
    }
    return L;
}

/**
 * batchVerify(proofs, publicSignalsArray, vk, curve)
 *
 * @param {Array}  proofs              - array of snarkjs proof objects {pi_a, pi_b, pi_c}
 * @param {Array}  publicSignalsArray  - array of publicSignals arrays (one per proof)
 * @param {Object} vk                  - snarkjs verification key object
 * @param {Object} curve               - pre-built ffjavascript bn128 curve (from buildBatchCurve)
 * @returns {Promise<{valid: boolean, pairingCount: number}>}
 */
async function batchVerify(proofs, publicSignalsArray, vk, curve) {
    if (proofs.length === 0) throw new Error("Empty proof list");
    if (proofs.length !== publicSignalsArray.length) {
        throw new Error("proofs and publicSignalsArray length mismatch");
    }

    // JSON stores field elements as decimal strings; convert to BigInts first,
    // exactly as snarkjs.groth16.verify does internally via unstringifyBigInts.
    vk              = unstringifyBigInts(vk);
    proofs          = unstringifyBigInts(proofs);
    publicSignalsArray = unstringifyBigInts(publicSignalsArray);

    const G1      = curve.G1;
    const G2      = curve.G2;

    // -------------------------------------------------------
    // Load verification key points
    // -------------------------------------------------------
    const alpha1 = G1.fromObject(vk.vk_alpha_1);
    const beta2  = G2.fromObject(vk.vk_beta_2);
    const gamma2 = G2.fromObject(vk.vk_gamma_2);
    const delta2 = G2.fromObject(vk.vk_delta_2);

    // -------------------------------------------------------
    // For each proof j, sample ρ_j and accumulate:
    //   aggA_list : [(ρ_j·A_j, B_j), ...]  — k pairing pairs (left side)
    //   sumRho    : ∑ρ_j
    //   aggL      : ∑ρ_j·L_j               — aggregated input commitment
    //   aggC      : ∑ρ_j·C_j               — aggregated C point
    // -------------------------------------------------------
    const pairedAs = [];   // ρ_j·A_j for each j
    const Bs       = [];   // B_j for each j (G2, varies per proof)
    let sumRho     = BigInt(0);
    let aggL       = G1.zero;
    let aggC       = G1.zero;

    for (let j = 0; j < proofs.length; j++) {
        const rho = randomScalar();
        sumRho = (sumRho + rho) % FIELD_R;

        // Scale A_j by ρ_j
        const A_j     = G1.fromObject(proofs[j].pi_a);
        const rhoA_j  = G1.timesScalar(A_j, rho);
        pairedAs.push(rhoA_j);

        // B_j is a G2 point — cannot be aggregated (varies per proof)
        Bs.push(G2.fromObject(proofs[j].pi_b));

        // Compute L_j = IC[0] + ∑ pubSig_i · IC[i+1]
        const L_j    = computeL(publicSignalsArray[j], vk.IC, G1);
        const rhoL_j = G1.timesScalar(L_j, rho);
        aggL = G1.add(aggL, rhoL_j);

        // Scale C_j by ρ_j
        const C_j    = G1.fromObject(proofs[j].pi_c);
        const rhoC_j = G1.timesScalar(C_j, rho);
        aggC = G1.add(aggC, rhoC_j);
    }

    // ∑ρ_j · α  (aggregated alpha)
    const aggAlpha = G1.timesScalar(alpha1, sumRho);

    // -------------------------------------------------------
    // Build the k+3 pairing argument list for ONE pairingEq call:
    //
    //   k pairs:  (ρ_j·A_j,    B_j)         [left side, one per proof]
    //   1 pair:   (-∑ρ_j·α,    β)            [aggregated alpha, negated]
    //   1 pair:   (-∑ρ_j·L_j,  γ)            [aggregated L,     negated]
    //   1 pair:   (-∑ρ_j·C_j,  δ)            [aggregated C,     negated]
    //
    // pairingEq checks that the product of all pairings = 1 in GT.
    // Negating G1 points flips the sign in GT, turning the equality into
    // a product-equals-one check.
    // -------------------------------------------------------
    const args = [];

    // k pairs for the left side (B_j varies, so cannot collapse further)
    for (let j = 0; j < proofs.length; j++) {
        args.push(pairedAs[j], Bs[j]);
    }

    // 3 aggregated pairs (negated)
    args.push(G1.neg(aggAlpha), beta2);
    args.push(G1.neg(aggL),     gamma2);
    args.push(G1.neg(aggC),     delta2);

    // -------------------------------------------------------
    // THE KEY OPERATION:
    //   One pairingEq call = (k+3) Miller loops + 1 final exponentiation
    //   vs k individual verifications = 3k Miller loops + k final exp
    // -------------------------------------------------------
    const valid = await curve.pairingEq(...args);

    return {
        valid,
        pairingCount: proofs.length + 3,   // k+3
    };
}

/**
 * Build the shared bn128 curve instance.
 * Create once before benchmarking; pass to every batchVerify call.
 * Call curve.terminate() when finished.
 */
async function buildBatchCurve() {
    return getCurveFromName("bn128");
}

module.exports = { batchVerify, buildBatchCurve };
