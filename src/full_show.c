/*
 * Zero-knowledge proof for full attribute disclosure
 */

#include "anon_cert.h"
#include <string.h>
#include <stdio.h>

// Generate full attribute disclosure proof
void full_show_prove(full_show_view_t *view, const system_params_t *params,
                     const certificate_t *cert) {
    memset(view, 0, sizeof(full_show_view_t));
    
    // Compute commitment C
    g1_point_t C;
    commit_attributes(&C, params, cert->m, cert->attr_count);
    
    // Re-randomization: overA = r * A, overB = r * (C - e*A)
    scalar_t r;
    random_scalar(r);
    
    // Convert r to little-endian for point multiplication
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
    
    // First round: U = alpha*C + beta*overA
    scalar_t alpha, beta;
    random_scalar(alpha);
    random_scalar(beta);
    
    // Convert alpha and beta to little-endian
    blst_scalar s_alpha, s_beta;
    blst_scalar_from_be_bytes(&s_alpha, alpha, 32);
    blst_scalar_from_be_bytes(&s_beta, beta, 32);
    scalar_t alpha_bytes, beta_bytes;
    blst_lendian_from_scalar(alpha_bytes, &s_alpha);
    blst_lendian_from_scalar(beta_bytes, &s_beta);
    
    g1_point_t alpha_C, beta_overA;
    g1_mul(&alpha_C, &C, alpha_bytes);
    g1_mul(&beta_overA, &view->overA, beta_bytes);
    g1_add(&view->U, &alpha_C, &beta_overA);
    
    // Verifier selects challenge c (simulated)
    byte challenge_seed[256];
    snprintf((char *)challenge_seed, sizeof(challenge_seed), "challenge:%s", 
             (char *)cert->m);
    
    hash_to_scalar(view->c, challenge_seed, strlen((char *)challenge_seed));
    
    // User computes response
    // s = alpha + r * c
    // Reuse already declared s_alpha, s_beta, s_r, s_e
    blst_scalar s_c;
    blst_scalar_from_be_bytes(&s_c, view->c, 32);
    
    blst_fr fr_alpha, fr_r, fr_c, fr_rc, fr_result;
    blst_fr_from_scalar(&fr_alpha, &s_alpha);
    blst_fr_from_scalar(&fr_r, &s_r);
    blst_fr_from_scalar(&fr_c, &s_c);
    
    blst_fr_mul(&fr_rc, &fr_r, &fr_c);
    blst_fr_add(&fr_result, &fr_alpha, &fr_rc);
    
    blst_scalar s_result;
    blst_scalar_from_fr(&s_result, &fr_result);
    // Use little-endian storage, consistent with format expected by g1_mul
    blst_lendian_from_scalar(view->s, &s_result);
    
    // t = beta - e * c
    // Reuse already declared s_beta and s_e (s_beta assigned at line 48, s_e assigned at line 34)
    
    blst_fr fr_beta, fr_e, fr_ec, fr_t;
    blst_fr_from_scalar(&fr_beta, &s_beta);
    blst_fr_from_scalar(&fr_e, &s_e);
    // fr_c already computed above, reuse
    
    blst_fr_mul(&fr_ec, &fr_e, &fr_c);
    blst_fr_sub(&fr_t, &fr_beta, &fr_ec);
    
    blst_scalar s_t;
    blst_scalar_from_fr(&s_t, &fr_t);
    // Use little-endian storage, consistent with format expected by g1_mul
    blst_lendian_from_scalar(view->t, &s_t);
    
    // Save cert_m for verification
    memcpy(view->cert_m, cert->m, cert->attr_count * 32);
    view->cert_m_len = cert->attr_count;
}

// Verify full attribute disclosure
bool full_show_verify(const system_params_t *params, const full_show_view_t *view) {
    // Reconstruct commitment C
    g1_point_t C;
    commit_attributes(&C, params, view->cert_m, view->cert_m_len);
    
    // Check signature core relation: e(overA, X2) == e(overB, g2)
    // Since overA = r * A, overB = r * (C - e*A)
    // Theoretically: e(overA, X2) = e(r*A, X2) = e(A, X2)^r
    // And e(overB, g2) = e(r*(C-e*A), g2) = e(C-e*A, g2)^r
    // Since e(C, g2) = e(A, X2+e*g2) = e(A, X2) * e(A, e*g2)
    // So e(C-e*A, g2) = e(C, g2) * e(-e*A, g2) = e(A, X2) * e(A, e*g2) * e(A, g2)^(-e)
    // = e(A, X2) * e(A, g2)^e * e(A, g2)^(-e) = e(A, X2)
    // Therefore e(overB, g2) = e(A, X2)^r = e(overA, X2)
    
    // But in actual verification, due to possible precision issues in pairing computation, we use same method as certificate verification
    // Verify e(overA, X2) == e(overB, g2)
    bool pairing_ok = pairing_check(&view->overA, &params->X2, &view->overB, &params->g2);
    if (!pairing_ok) {
        return false;
    }
    
    // Check knowledge proof relation: U + c*overB == s*C + t*overA
    // Note: view->s and view->t are already in little-endian format
    g1_point_t c_overB, s_C, t_overA, left, right;
    
    // view->c needs to be converted to little-endian
    blst_scalar s_c;
    blst_scalar_from_be_bytes(&s_c, view->c, 32);
    scalar_t c_bytes;
    blst_lendian_from_scalar(c_bytes, &s_c);
    
    // view->s and view->t are already little-endian, use directly
    g1_mul(&c_overB, &view->overB, c_bytes);
    g1_add(&left, &view->U, &c_overB);
    
    g1_mul(&s_C, &C, view->s);
    g1_mul(&t_overA, &view->overA, view->t);
    g1_add(&right, &s_C, &t_overA);
    
    // Compare points
    byte left_bytes[96], right_bytes[96];
    blst_p1_serialize(left_bytes, &left);
    blst_p1_serialize(right_bytes, &right);
    
    bool result = memcmp(left_bytes, right_bytes, 96) == 0;
    
    return result;
}

