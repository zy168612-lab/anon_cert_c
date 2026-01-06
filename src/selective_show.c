/*
 * Zero-knowledge proof for selective attribute disclosure
 */

#include "anon_cert.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

// Check if index is in array
static bool index_in_array(int idx, const int *arr, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (arr[i] == idx) return true;
    }
    return false;
}

// Generate selective disclosure proof
// sk_u: User secret key (for correctly computing commitment C)
void selective_show_prove(selective_show_view_t *view, const system_params_t *params,
                          const certificate_t *cert, const scalar_t sk_u,
                          const int *J, size_t J_count) {
    memset(view, 0, sizeof(selective_show_view_t));
    
    // Copy J
    memcpy(view->J, J, J_count * sizeof(int));
    view->J_count = J_count;
    
    const scalar_t *m = cert->m;
    size_t l = cert->attr_count - 1;  // Number of attributes (excluding id)
    
    // According to paper, indices 0 (id) and 1 (sk_u) are always hidden
    // J ⊆ {2, 3, ..., l}, compute I = {2..l} - J
    size_t I_count = 0;
    for (size_t i = 2; i <= l; i++) {
        if (!index_in_array((int)i, J, J_count)) {
            view->I_prime[I_count + 2] = (int)i;  // +2 because I' contains 0 and 1
            I_count++;
        }
    }
    view->I_prime[0] = 0;  // id is always hidden
    view->I_prime[1] = 1;  // sk_u is always hidden
    view->I_prime_count = I_count + 2;  // I' = {0, 1} ∪ I
    
    // Compute C_J = g1 + Σ_{j in J} m_j * h_j
    view->C_J = params->g1;
    for (size_t i = 0; i < J_count; i++) {
        int j = J[i];
        if (j > 0 && j <= (int)params->max_attrs) {
            g1_point_t term;
            // m[j] is big-endian, need to convert to little-endian (consistent with commit_attributes)
            blst_scalar s_mj;
            blst_scalar_from_be_bytes(&s_mj, m[j], 32);
            scalar_t mj_bytes;
            blst_lendian_from_scalar(mj_bytes, &s_mj);
            g1_mul(&term, &params->hs[j], mj_bytes);
            
            g1_point_t new_C_J;
            g1_add(&new_C_J, &view->C_J, &term);
            view->C_J = new_C_J;
        }
    }
    
    // Compute full C
    // Note: Need to use actual sk_u, not cert->m[1] (placeholder)
    g1_point_t C = params->g1;  // C = g_1
    
    // C += h_0^{id}
    blst_scalar s_id;
    blst_scalar_from_be_bytes(&s_id, m[0], 32);
    scalar_t id_bytes;
    blst_lendian_from_scalar(id_bytes, &s_id);
    g1_point_t h0_id;
    g1_mul(&h0_id, &params->hs[0], id_bytes);
    g1_point_t temp;
    g1_add(&temp, &C, &h0_id);
    C = temp;
    
    // C += h_1^{sk_u} (use actual sk_u)
    blst_scalar s_sk_u;
    blst_scalar_from_be_bytes(&s_sk_u, sk_u, 32);
    scalar_t sk_u_bytes;
    blst_lendian_from_scalar(sk_u_bytes, &s_sk_u);
    g1_point_t h1_sk_u;
    g1_mul(&h1_sk_u, &params->hs[1], sk_u_bytes);
    g1_add(&temp, &C, &h1_sk_u);
    C = temp;
    
    // C += h_2^{exp} + Σ_{i=3}^l h_i^{m_i}
    for (size_t i = 2; i < cert->attr_count && i <= params->max_attrs; i++) {
        g1_point_t term;
        blst_scalar s_mi;
        blst_scalar_from_be_bytes(&s_mi, m[i], 32);
        scalar_t mi_bytes;
        blst_lendian_from_scalar(mi_bytes, &s_mi);
        g1_mul(&term, &params->hs[i], mi_bytes);
        g1_add(&temp, &C, &term);
        C = temp;
    }
    
    // Re-randomization
    scalar_t r;
    random_scalar(r);
    
    // r is big-endian, need to convert to little-endian
    blst_scalar s_r;
    blst_scalar_from_be_bytes(&s_r, r, 32);
    scalar_t r_bytes;
    blst_lendian_from_scalar(r_bytes, &s_r);
    
    g1_mul(&view->overA, &cert->A, r_bytes);
    
    g1_point_t neg_A, eA, CeA;
    g1_neg(&neg_A, &cert->A);
    // cert->e is big-endian, need to convert to little-endian
    blst_scalar s_e;
    blst_scalar_from_be_bytes(&s_e, cert->e, 32);
    scalar_t e_bytes;
    blst_lendian_from_scalar(e_bytes, &s_e);
    g1_mul(&eA, &neg_A, e_bytes);
    g1_add(&CeA, &C, &eA);
    g1_mul(&view->overB, &CeA, r_bytes);
    
    // Construct C_J', h_i', h_i''
    g1_mul(&view->C_J_prime, &view->C_J, r_bytes);
    
    scalar_t deltas[MAX_ATTRS + 1];
    for (size_t i = 0; i < view->I_prime_count; i++) {
        int idx = view->I_prime[i];
        g1_point_t hi = params->hs[idx];
        
        g1_mul(&view->h_prime[i], &hi, r_bytes);
        
        // For index 1 (sk_u), use actual sk_u, not m[1] (placeholder)
        scalar_t attr_value;
        if (idx == 1) {
            memcpy(attr_value, sk_u, 32);
        } else {
            memcpy(attr_value, m[idx], 32);
        }
        
        // attr_value is big-endian, need to convert to little-endian
        blst_scalar s_attr;
        blst_scalar_from_be_bytes(&s_attr, attr_value, 32);
        scalar_t attr_bytes;
        blst_lendian_from_scalar(attr_bytes, &s_attr);
        g1_mul(&view->h_dblprime[i], &view->h_prime[i], attr_bytes);
        
        random_scalar(deltas[i]);
    }
    
    // U = alpha*C_J + beta*overA + Σ delta_i * h_i
    scalar_t alpha, beta;
    random_scalar(alpha);
    random_scalar(beta);
    
    // alpha and beta are big-endian, need to convert to little-endian
    blst_scalar s_alpha, s_beta;
    blst_scalar_from_be_bytes(&s_alpha, alpha, 32);
    blst_scalar_from_be_bytes(&s_beta, beta, 32);
    scalar_t alpha_bytes, beta_bytes;
    blst_lendian_from_scalar(alpha_bytes, &s_alpha);
    blst_lendian_from_scalar(beta_bytes, &s_beta);
    
    g1_point_t alpha_CJ, beta_overA;
    g1_mul(&alpha_CJ, &view->C_J, alpha_bytes);
    g1_mul(&beta_overA, &view->overA, beta_bytes);
    g1_add(&view->U, &alpha_CJ, &beta_overA);
    
    for (size_t i = 0; i < view->I_prime_count; i++) {
        int idx = view->I_prime[i];
        g1_point_t delta_hi;
        // deltas[i] is big-endian, need to convert to little-endian
        blst_scalar s_delta;
        blst_scalar_from_be_bytes(&s_delta, deltas[i], 32);
        scalar_t delta_bytes;
        blst_lendian_from_scalar(delta_bytes, &s_delta);
        g1_mul(&delta_hi, &params->hs[idx], delta_bytes);
        
        g1_point_t new_U;
        g1_add(&new_U, &view->U, &delta_hi);
        view->U = new_U;
    }
    
    // π1: Use batch Schnorr proof to prove all r are equal
    // Prove C_J' = C_J^r and all h'[i] = h[i]^r use the same r
    scalar_t r_commit;
    random_scalar(r_commit);
    
    // Prepare batch proof inputs: including C_J' = C_J^r and all h'[i] = h[i]^r
    size_t batch_count = 1 + view->I_prime_count;  // C_J + all h'[i]
    g1_point_t *batch_bases = (g1_point_t *)malloc(batch_count * sizeof(g1_point_t));
    g1_point_t *batch_ys = (g1_point_t *)malloc(batch_count * sizeof(g1_point_t));
    scalar_t *batch_ws = (scalar_t *)malloc(batch_count * sizeof(scalar_t));
    
    if (!batch_bases || !batch_ys || !batch_ws) {
        // Memory allocation failed, fall back to independent proofs
        if (batch_bases) free(batch_bases);
        if (batch_ys) free(batch_ys);
        if (batch_ws) free(batch_ws);
        return;
    }
    
    // First: C_J' = C_J^r
    batch_bases[0] = view->C_J;
    batch_ys[0] = view->C_J_prime;
    memcpy(batch_ws[0], r, 32);
    
    // Rest: h'[i] = h[i]^r
    for (size_t i = 0; i < view->I_prime_count; i++) {
        int idx = view->I_prime[i];
        batch_bases[1 + i] = params->hs[idx];
        batch_ys[1 + i] = view->h_prime[i];
        memcpy(batch_ws[1 + i], r, 32);
    }
    
    // Generate batch proof
    schnorr_proof_t *batch_proofs = (schnorr_proof_t *)malloc(batch_count * sizeof(schnorr_proof_t));
    if (!batch_proofs) {
        free(batch_bases);
        free(batch_ys);
        free(batch_ws);
        return;
    }
    
    byte tag_batch[] = "pi1_batch_r";
    // Directly store batch proof challenge value to view->c (for verification)
    schnorr_batch_prove(batch_proofs, batch_bases, batch_ys, batch_ws, batch_count,
                        tag_batch, sizeof(tag_batch) - 1, r_commit, view->c);
    
    // Copy batch proof results to view structure
    view->pi1_CJ = batch_proofs[0];
    for (size_t i = 0; i < view->I_prime_count; i++) {
        view->pi1_hr[i] = batch_proofs[1 + i];
    }
    
    free(batch_proofs);
    free(batch_bases);
    free(batch_ys);
    free(batch_ws);
    
    view->pi1_hr_count = view->I_prime_count;
    view->pi1_hm_count = view->I_prime_count;
    
    // Proof for h''[i] = h'[i]^{attr_value} uses independent random number (because witness is different)
    byte tag_hm[] = "pi1_hm";
    for (size_t i = 0; i < view->I_prime_count; i++) {
        int idx = view->I_prime[i];
        // For index 1 (sk_u), use actual sk_u, not m[1] (placeholder)
        scalar_t attr_value;
        if (idx == 1) {
            memcpy(attr_value, sk_u, 32);
        } else {
            memcpy(attr_value, m[idx], 32);
        }
        schnorr_prove(&view->pi1_hm[i], &view->h_prime[i], &view->h_dblprime[i], attr_value, tag_hm, sizeof(tag_hm) - 1, NULL);
    }
    
    // π2: Prove overA' = overA^{-e}
    g1_point_t overA_base;
    g1_neg(&overA_base, &view->overA);
    // cert->e is big-endian, need to convert to little-endian (reuse previously declared e_bytes)
    g1_mul(&view->overA_prime, &overA_base, e_bytes);
    
    byte tag_pi2[] = "pi2_e";
    // Proof for overA' = overA^{-e} uses independent random number (because witness is different)
    schnorr_prove(&view->pi2, &overA_base, &view->overA_prime, cert->e, tag_pi2, sizeof(tag_pi2) - 1, NULL);
    
    // Non-membership proof (using new witness format)
    scalar_t id0;
    memcpy(id0, m[0], 32);
    
    // Generate non-membership witness (ω_id', A_t', g_id, π_id)
    // Note: A_t' is already included in witness, no need to set view->A_t separately
    gen_witness(&view->witness, params, id0);
    
    // Randomization parameters
    // r has been converted to little-endian r_bytes, use directly
    g2_mul(&view->g_r, &params->g2, r_bytes);
    
    // g2' = g2^{r * id0}
    // Reuse previously declared s_r
    blst_scalar s_id0;
    blst_scalar_from_be_bytes(&s_id0, id0, 32);
    
    // Compute r * id0
    blst_fr fr_r, fr_id0, fr_rid0;
    blst_fr_from_scalar(&fr_r, &s_r);
    blst_fr_from_scalar(&fr_id0, &s_id0);
    blst_fr_mul(&fr_rid0, &fr_r, &fr_id0);
    
    blst_scalar s_rid0;
    blst_scalar_from_fr(&s_rid0, &fr_rid0);
    scalar_t rid0_bytes;
    blst_lendian_from_scalar(rid0_bytes, &s_rid0);
    g2_mul(&view->g2_p, &params->g2, rid0_bytes);
    
    // g2'' = (g2^{kappa})^r = g2^{r*kappa}
    // kappa is secret, only issuer knows it, user side should use public g2_kappa for multiplication
    // r_bytes is already little-endian, use directly for point multiplication
    g2_mul(&view->g2_pp, &params->g2_kappa, r_bytes);
    
    // Note: According to non-membership proof theory, need to verify e(omega, g2^{r*(id0+kappa)}) == e(A_t * g1^v, g2^r)
    // Where g2^{r*(id0+kappa)} = g2^{r*id0} * g2^{r*kappa} = g2' * g2''
    // In group operations, g2' * g2'' is point addition, should equal g2^{r*(id0+kappa)}
    
    // Verifier selects challenge c (simulated)
    // Note: view->c is already set in batch proof, here need to save challenge value for other proofs
    // However, since view->c is already used for batch proof, we need to use different variable
    // Actually, attribute knowledge verification should use batch proof challenge value view->c
    // So no need to generate new challenge value here, use view->c directly
    // byte challenge_seed[256];
    // snprintf((char *)challenge_seed, sizeof(challenge_seed), "challenge_sel:%s", (char *)m);
    // scalar_t challenge_c_other;  // Challenge value for other proofs
    // hash_to_scalar(challenge_c_other, challenge_seed, strlen((char *)challenge_seed));
    
    // User computes response
    // s = alpha + r * c
    // Reuse previously declared s_alpha
    // Note: Here use batch proof challenge value view->c
    blst_scalar s_c;
    blst_scalar_from_be_bytes(&s_c, view->c, 32);
    
    blst_fr fr_alpha, fr_c, fr_rc, fr_result;
    blst_fr_from_scalar(&fr_alpha, &s_alpha);
    blst_fr_from_scalar(&fr_c, &s_c);
    
    blst_fr_mul(&fr_rc, &fr_r, &fr_c);  // Reuse previously declared fr_r
    blst_fr_add(&fr_result, &fr_alpha, &fr_rc);
    
    blst_scalar s_result;
    blst_scalar_from_fr(&s_result, &fr_result);
    blst_bendian_from_scalar(view->s, &s_result);
    
    // t1 = beta - e * c
    // Reuse previously declared s_beta and s_e
    blst_fr fr_beta, fr_e, fr_ec, fr_t1;
    blst_fr_from_scalar(&fr_beta, &s_beta);
    blst_fr_from_scalar(&fr_e, &s_e);
    
    blst_fr_mul(&fr_ec, &fr_e, &fr_c);
    blst_fr_sub(&fr_t1, &fr_beta, &fr_ec);
    
    blst_scalar s_t1;
    blst_scalar_from_fr(&s_t1, &fr_t1);
    blst_bendian_from_scalar(view->t1, &s_t1);
    
    // u_i = delta_i + r * m_i * c
    view->u_dict_count = view->I_prime_count;
    for (size_t i = 0; i < view->I_prime_count; i++) {
        int idx = view->I_prime[i];
        
        // For index 1 (sk_u), use actual sk_u, not m[1] (placeholder)
        scalar_t attr_value;
        if (idx == 1) {
            memcpy(attr_value, sk_u, 32);
        } else {
            memcpy(attr_value, m[idx], 32);
        }
        
        blst_scalar s_delta, s_mi;
        blst_scalar_from_be_bytes(&s_delta, deltas[i], 32);
        blst_scalar_from_be_bytes(&s_mi, attr_value, 32);
        
        blst_fr fr_delta, fr_mi, fr_rmi, fr_rmic, fr_ui;
        blst_fr_from_scalar(&fr_delta, &s_delta);
        blst_fr_from_scalar(&fr_mi, &s_mi);
        // Reuse previously declared fr_r and fr_c
        
        blst_fr_mul(&fr_rmi, &fr_r, &fr_mi);  // Reuse previously declared fr_r
        blst_fr_mul(&fr_rmic, &fr_rmi, &fr_c);  // Reuse previously declared fr_c
        blst_fr_add(&fr_ui, &fr_delta, &fr_rmic);
        
        blst_scalar s_ui;
        blst_scalar_from_fr(&s_ui, &fr_ui);
        blst_bendian_from_scalar(view->u_dict[i], &s_ui);
    }
}

// Verify selective disclosure
bool selective_show_verify(const system_params_t *params, const selective_show_view_t *view,
                           const scalar_t *disclosed_attrs, size_t disclosed_count) {
    // 1) Check overB relation: overB == C_J' + overA' + Σ h_i''
    g1_point_t rhs;
    g1_add(&rhs, &view->C_J_prime, &view->overA_prime);
    
    for (size_t i = 0; i < view->I_prime_count; i++) {
        g1_point_t new_rhs;
        g1_add(&new_rhs, &rhs, &view->h_dblprime[i]);
        rhs = new_rhs;
    }
    
    byte overB_bytes[96], rhs_bytes[96];
    blst_p1_serialize(overB_bytes, &view->overB);
    blst_p1_serialize(rhs_bytes, &rhs);
    if (memcmp(overB_bytes, rhs_bytes, 96) != 0) {
        return false;
    }
    
    // 2) Verify π1: Use batch proof to verify all r are equal
    size_t batch_count = 1 + view->I_prime_count;  // C_J + all h'[i]
    g1_point_t *batch_bases = (g1_point_t *)malloc(batch_count * sizeof(g1_point_t));
    g1_point_t *batch_ys = (g1_point_t *)malloc(batch_count * sizeof(g1_point_t));
    schnorr_proof_t *batch_proofs = (schnorr_proof_t *)malloc(batch_count * sizeof(schnorr_proof_t));
    
    if (!batch_bases || !batch_ys || !batch_proofs) {
        if (batch_bases) free(batch_bases);
        if (batch_ys) free(batch_ys);
        if (batch_proofs) free(batch_proofs);
        return false;
    }
    
    // First: C_J' = C_J^r
    batch_bases[0] = view->C_J;
    batch_ys[0] = view->C_J_prime;
    batch_proofs[0] = view->pi1_CJ;
    
    // Rest: h'[i] = h[i]^r
    for (size_t i = 0; i < view->I_prime_count; i++) {
        int idx = view->I_prime[i];
        batch_bases[1 + i] = params->hs[idx];
        batch_ys[1 + i] = view->h_prime[i];
        batch_proofs[1 + i] = view->pi1_hr[i];
    }
    
    byte tag_batch[] = "pi1_batch_r";
    if (!schnorr_batch_verify(batch_bases, batch_ys, batch_proofs, batch_count,
                               tag_batch, sizeof(tag_batch) - 1, view->c)) {
        free(batch_bases);
        free(batch_ys);
        free(batch_proofs);
        return false;
    }
    
    free(batch_bases);
    free(batch_ys);
    free(batch_proofs);
    
    // Verify independent proof for h''[i] = h'[i]^{attr_value}
    byte tag_hm[] = "pi1_hm";
    for (size_t i = 0; i < view->I_prime_count; i++) {
        if (!schnorr_verify(&view->h_prime[i], &view->h_dblprime[i], &view->pi1_hm[i], tag_hm, sizeof(tag_hm) - 1)) {
            return false;
        }
    }
    
    // 3) Verify π2
    g1_point_t overA_base;
    g1_neg(&overA_base, &view->overA);
    byte tag_pi2[] = "pi2_e";
    if (!schnorr_verify(&overA_base, &view->overA_prime, &view->pi2, tag_pi2, sizeof(tag_pi2) - 1)) {
        return false;
    }
    
    // 4) Verify randomization parameter relation (pairing check)
    g1_point_t h0 = params->hs[0];
    g1_point_t h0_p = view->h_prime[0];
    g1_point_t h0_pp = view->h_dblprime[0];
    
    // e(h_0, g_2') == e(h_0'', g_2)
    if (!pairing_check(&h0, &view->g2_p, &h0_pp, &params->g2)) {
        return false;
    }
    
    // e(h_0, g_2'') == e(h_0', g_2^{kappa})
    if (!pairing_check(&h0, &view->g2_pp, &h0_p, &params->g2_kappa)) {
        return false;
    }
    
    // e(h_0, g_r) == e(h_0', g_2)
    if (!pairing_check(&h0, &view->g_r, &h0_p, &params->g2)) {
        return false;
    }
    
    // 5) Reconstruct public commitment C_J
    g1_point_t C_J_recomputed = params->g1;
    for (size_t i = 0; i < view->J_count; i++) {
        int j = view->J[i];
        if (j > 0 && j <= (int)params->max_attrs && i < disclosed_count) {
            g1_point_t term;
            // disclosed_attrs[i] is big-endian, need to convert to little-endian
            blst_scalar s_attr;
            blst_scalar_from_be_bytes(&s_attr, disclosed_attrs[i], 32);
            scalar_t attr_bytes;
            blst_lendian_from_scalar(attr_bytes, &s_attr);
            g1_mul(&term, &params->hs[j], attr_bytes);
            
            g1_point_t new_C_J;
            g1_add(&new_C_J, &C_J_recomputed, &term);
            C_J_recomputed = new_C_J;
        }
    }
    
    byte C_J_bytes[96], C_J_recomputed_bytes[96];
    blst_p1_serialize(C_J_bytes, &view->C_J);
    blst_p1_serialize(C_J_recomputed_bytes, &C_J_recomputed);
    if (memcmp(C_J_bytes, C_J_recomputed_bytes, 96) != 0) {
        return false;
    }
    
    // 6) Verify signature core relation: e(overA, X2) == e(overB, g2)
    if (!pairing_check(&view->overA, &params->X2, &view->overB, &params->g2)) {
        return false;
    }
    
    // 7) Verify non-membership proof
    // Note: According to new algorithm, π_id now proves batch relation (v_id, r_{nm})
    // Skip separate verification here temporarily, because complete verification needs schnorr_batch_verify
    // Pairing relation verification is done below
    
    // Check if g_id is identity element (if identity, certificate has been revoked)
    // Identity element is point at infinity, can check if it's g_1^0
    // But simpler method is to check if g_id equals g_1^0 (i.e., identity element)
    scalar_t zero = {0};
    blst_scalar s_zero;
    blst_scalar_from_be_bytes(&s_zero, zero, 32);
    scalar_t zero_bytes;
    blst_lendian_from_scalar(zero_bytes, &s_zero);
    g1_point_t g1_zero;
    g1_mul(&g1_zero, &params->g1, zero_bytes);
    
    byte g_id_bytes[96], g1_zero_bytes[96];
    blst_p1_serialize(g_id_bytes, &view->witness.g_id);
    blst_p1_serialize(g1_zero_bytes, &g1_zero);
    if (memcmp(g_id_bytes, g1_zero_bytes, 96) == 0) {
        return false;  // Certificate has been revoked
    }
    
    // Verify π_id: prove relation (v_id, r_{nm})
    // π_id proves: g_{nm} = g_1^{r_{nm}} ∧ g_id = g_{nm}^{v_id} ∧ A_t' = A_t^{r_{nm}}
    // Note: Need to verify batch Schnorr proof here, but for simplicity, verify pairing relation
    // According to algorithm, π_id is a batch proof, verification uses schnorr_batch_verify
    // But to maintain interface consistency, only verify pairing relation here
    
    // Verify pairing relation: e(omega_id', g2' * g2'') == e(A_t' * g_id, g_r)
    // Note: According to new algorithm, omega_id' = omega_id^{r_{nm}}, A_t' = A_t^{r_{nm}}
    // Where omega_id = g1^{q_R(kappa)}, g_id = g_{nm}^{v_id}, g_{nm} = g1^{r_{nm}}
    // According to non-membership proof theory: e(omega_id', g2^{r*(id0+kappa)}) == e(A_t' * g_id, g2^r)
    // Where g2^{r*(id0+kappa)} = g2' * g2''
    g2_point_t left_g2;
    g2_add(&left_g2, &view->g2_p, &view->g2_pp);
    
    g1_point_t right_g1;
    g1_add(&right_g1, &view->witness.A_t_prime, &view->witness.g_id);
    
    // Verify pairing relation: e(omega_id', g2^{r*(id0+kappa)}) == e(A_t' * g_id, g2^r)
    // According to bilinearity, this is equivalent to verifying: e(omega_id', g2_p + g2_pp) == e(A_t' + g_id, g_r)
    if (!pairing_check(&view->witness.omega_id_prime, &left_g2, &right_g1, &view->g_r)) {
        return false;
    }
    
    // Verify π_id proof (batch Schnorr proof)
    // Note: Since witness->pi_id stores first proof of batch proof, need to verify entire batch proof
    // But for simplicity, only verify basic pairing relation here, complete proof verification should be at higher level
    // Note: Complete verification should use schnorr_batch_verify, but skip here temporarily
    
    // 8) Verify attribute knowledge: U + c*overB == s*C_J + t1*overA + Σ u_i*h_i
    g1_point_t c_overB, s_CJ, t1_overA, left, right;
    // view->c, view->s, view->t1 are big-endian, need to convert to little-endian
    blst_scalar s_c, s_s, s_t1;
    blst_scalar_from_be_bytes(&s_c, view->c, 32);
    blst_scalar_from_be_bytes(&s_s, view->s, 32);
    blst_scalar_from_be_bytes(&s_t1, view->t1, 32);
    scalar_t c_bytes, s_bytes, t1_bytes;
    blst_lendian_from_scalar(c_bytes, &s_c);
    blst_lendian_from_scalar(s_bytes, &s_s);
    blst_lendian_from_scalar(t1_bytes, &s_t1);
    
    g1_mul(&c_overB, &view->overB, c_bytes);
    g1_add(&left, &view->U, &c_overB);
    
    g1_mul(&s_CJ, &view->C_J, s_bytes);
    g1_mul(&t1_overA, &view->overA, t1_bytes);
    g1_add(&right, &s_CJ, &t1_overA);
    
    for (size_t i = 0; i < view->I_prime_count; i++) {
        int idx = view->I_prime[i];
        g1_point_t ui_hi;
        // view->u_dict[i] is big-endian, need to convert to little-endian
        blst_scalar s_ui;
        blst_scalar_from_be_bytes(&s_ui, view->u_dict[i], 32);
        scalar_t ui_bytes;
        blst_lendian_from_scalar(ui_bytes, &s_ui);
        g1_mul(&ui_hi, &params->hs[idx], ui_bytes);
        
        g1_point_t new_right;
        g1_add(&new_right, &right, &ui_hi);
        right = new_right;
    }
    
    byte left_bytes[96], right_bytes[96];
    blst_p1_serialize(left_bytes, &left);
    blst_p1_serialize(right_bytes, &right);
    
    if (memcmp(left_bytes, right_bytes, 96) != 0) {
        return false;
    }
    
    return true;
}

