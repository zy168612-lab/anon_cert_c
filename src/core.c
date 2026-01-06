/*
 * Core functionality implementation: system initialization, certificate issuance, verification, etc.
 */

#include "anon_cert.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

// Check if blst_fr is zero (check all data)
static bool fr_is_zero(const blst_fr *fr) {
    uint64_t fr_uint64[4];
    blst_uint64_from_fr(fr_uint64, fr);
    // Check if all 4 uint64_t are zero
    return (fr_uint64[0] == 0 && fr_uint64[1] == 0 && 
            fr_uint64[2] == 0 && fr_uint64[3] == 0);
}

// Check if ID already exists
static bool id_exists(const issuer_keys_t *issuer_keys, const scalar_t id) {
    if (!issuer_keys->issued_ids || issuer_keys->issued_count == 0) {
        return false;
    }
    
    for (size_t i = 0; i < issuer_keys->issued_count; i++) {
        if (scalar_eq(issuer_keys->issued_ids[i], id)) {
            return true;
        }
    }
    return false;
}

// Allocate new ID (randomly select in mod r space, and check if already exists)
static bool allocate_id(scalar_t out_id, issuer_keys_t *issuer_keys) {
    const int MAX_ATTEMPTS = 1000;  // Maximum number of attempts
    
    // If capacity insufficient, expand memory
    if (issuer_keys->issued_count >= issuer_keys->issued_capacity) {
        size_t new_capacity = issuer_keys->issued_capacity * 2;
        if (new_capacity < issuer_keys->issued_capacity + 1) {
            new_capacity = issuer_keys->issued_capacity + 1;
        }
        scalar_t *new_issued_ids = (scalar_t *)realloc(issuer_keys->issued_ids, new_capacity * sizeof(scalar_t));
        if (!new_issued_ids) {
            return false;
        }
        issuer_keys->issued_ids = new_issued_ids;
        issuer_keys->issued_capacity = new_capacity;
    }
    
    // Try to generate random ID until finding one that doesn't exist
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        // Generate random ID in mod r space
        random_scalar_mod_r(out_id);
        
        // Check if already exists
        if (!id_exists(issuer_keys, out_id)) {
            // Add to issued ID list
            memcpy(issuer_keys->issued_ids[issuer_keys->issued_count], out_id, 32);
            issuer_keys->issued_count++;
            return true;
        }
    }
    
    // If all attempts fail, return false
    return false;
}

// System initialization
void setup(system_params_t *params, issuer_keys_t *issuer_keys, size_t max_attrs, size_t q) {
    memset(params, 0, sizeof(system_params_t));
    params->max_attrs = max_attrs;
    
    // Initialize dynamically allocated pointers to NULL
    params->g1_kappa_powers = NULL;
    params->batch_poly_coeffs = NULL;
    params->batch_poly_counts = NULL;
    params->accum_values = NULL;
    
    // Initialize issued_ids in issuer keys (confidential information)
    issuer_keys->issued_ids = NULL;
    issuer_keys->issued_count = 0;
    issuer_keys->issued_capacity = 0;
    
    // Get G1 and G2 generators
    const blst_p1 *g1_gen = blst_p1_generator();
    const blst_p2 *g2_gen = blst_p2_generator();
    params->g1 = *g1_gen;
    params->g2 = *g2_gen;
    
    // Generate attribute bases h_0 .. h_l
    // Use hash_to_curve method to avoid exposing logarithmic relations between hs
    for (size_t i = 0; i <= max_attrs; i++) {
        byte seed[64];
        snprintf((char *)seed, sizeof(seed), "h:%zu", i);
        
        // Directly use hash_to_g1 to map seed to G1 point
        hash_to_g1(&params->hs[i], seed, strlen((char *)seed));
    }
    
    // Issuer keys (only stored in issuer_keys, public parameters don't store private key)
    byte issuer_sk_seed[] = "issuer_sk";
    hash_to_scalar(issuer_keys->x, issuer_sk_seed, sizeof(issuer_sk_seed) - 1);
    // issuer_keys->x is big-endian, need to convert to little-endian for g2_mul
    blst_scalar s_x;
    blst_scalar_from_be_bytes(&s_x, issuer_keys->x, 32);
    scalar_t x_bytes;
    blst_lendian_from_scalar(x_bytes, &s_x);
    g2_mul(&params->X2, &params->g2, x_bytes);
    
    // Initialize accumulator
    setup_accumulator(params, issuer_keys, q);
    
    // Add default id=0 to revocation list
    scalar_t default_id = {0};
    revoke_id(params, issuer_keys, default_id);
    
    // Add default id=0 to issued ID list (in issuer_keys)
    if (issuer_keys->issued_count >= issuer_keys->issued_capacity) {
        size_t new_capacity = issuer_keys->issued_capacity * 2;
        if (new_capacity < issuer_keys->issued_capacity + 1) {
            new_capacity = issuer_keys->issued_capacity + 1;
        }
        scalar_t *new_issued_ids = (scalar_t *)realloc(issuer_keys->issued_ids, new_capacity * sizeof(scalar_t));
        if (new_issued_ids) {
            issuer_keys->issued_ids = new_issued_ids;
            issuer_keys->issued_capacity = new_capacity;
        }
    }
    if (issuer_keys->issued_ids) {
        memcpy(issuer_keys->issued_ids[issuer_keys->issued_count], default_id, 32);
        issuer_keys->issued_count++;
    }
}

// Attribute commitment
void commit_attributes(g1_point_t *C, const system_params_t *params,
                       const scalar_t *m, size_t m_len) {
    // C = g1 + Σ m_i * h_i
    *C = params->g1;
    
    for (size_t i = 0; i < m_len && i <= params->max_attrs; i++) {
        g1_point_t term;
        // m[i] is big-endian, need to convert to little-endian
        blst_scalar s_mi;
        blst_scalar_from_be_bytes(&s_mi, m[i], 32);
        scalar_t mi_bytes;
        blst_lendian_from_scalar(mi_bytes, &s_mi);
        g1_mul(&term, &params->hs[i], mi_bytes);
        
        g1_point_t new_C;
        g1_add(&new_C, C, &term);
        *C = new_C;
    }
}

// User generates request (Phase 1: Request)
// According to paper algorithm, user generates sk_u and M_1 = h_1^{sk_u}, and zero-knowledge proof π_sk
void user_generate_request(scalar_t sk_u, g1_point_t *M1, schnorr_proof_t *pi_sk,
                           const system_params_t *params) {
    // Step 1: Generate user secret key
    random_scalar(sk_u);
    
    // Step 2: Compute M_1 = h_1^{sk_u}
    // Note: h_1 is params->hs[1] (index starts from 0, h_0 is base for id, h_1 is base for sk_u)
    blst_scalar s_sk_u;
    blst_scalar_from_be_bytes(&s_sk_u, sk_u, 32);
    scalar_t sk_u_bytes;
    blst_lendian_from_scalar(sk_u_bytes, &s_sk_u);
    g1_mul(M1, &params->hs[1], sk_u_bytes);
    
    // Step 3: Generate zero-knowledge proof π_sk: prove knowledge of sk_u such that M_1 = h_1^{sk_u}
    byte tag_pi_sk[] = "pi_sk_u";
    schnorr_prove(pi_sk, &params->hs[1], M1, sk_u, tag_pi_sk, sizeof(tag_pi_sk) - 1, NULL);
}

// Issuer verifies request and generates credential (Phase 2: Verification and Generation)
// According to paper algorithm, issuer verifies π_sk, allocates id and exp, generates signature
bool issuer_verify_and_generate(certificate_t *cert, system_params_t *params,
                                const issuer_keys_t *issuer_keys,
                                const g1_point_t *M1, const schnorr_proof_t *pi_sk,
                                const scalar_t *user_attrs, size_t user_attrs_len,
                                uint64_t validity_duration) {
    memset(cert, 0, sizeof(certificate_t));
    
    // Step 4: Verify zero-knowledge proof π_sk
    byte tag_pi_sk[] = "pi_sk_u";
    if (!schnorr_verify(&params->hs[1], M1, pi_sk, tag_pi_sk, sizeof(tag_pi_sk) - 1)) {
        return false;  // Verification failed
    }
    
    // Step 5: Allocate identifier and expiration time
    // Allocate ID (randomly select in mod r space, and check if already exists)
    // Note: issuer_keys is not const, because allocate_id needs to modify issued_ids
    scalar_t m0;  // m_0 = id
    if (!allocate_id(m0, (issuer_keys_t *)issuer_keys)) {
        return false;  // ID allocation failed
    }
    
    // Compute expiration time exp = current_time + validity_duration
    // validity_duration is time length in seconds (lifetime)
    
    // Get current time (Unix timestamp, seconds)
    time_t current_time = time(NULL);
    if (current_time == (time_t)-1) {
        return false;  // Failed to get time
    }
    
    // Compute expiration time = current time + validity_duration (seconds)
    uint64_t expiration_time = (uint64_t)current_time + validity_duration;
    
    // Convert expiration time to scalar m_2 = exp
    scalar_t m2;
    memset(m2, 0, 32);
    for (int i = 7; i >= 0; i--) {
        m2[31 - i] = (byte)(expiration_time >> (i * 8));
    }
    
    // Step 6: Compute commitment C = g_1 * h_0^{id} * M_1 * h_2^{exp} * ∏_{i=3}^l h_i^{m_i}
    // Note: M_1 = h_1^{sk_u}, so C contains sk_u
    g1_point_t C = params->g1;  // C = g_1
    
    // C += h_0^{id}
    blst_scalar s_id;
    blst_scalar_from_be_bytes(&s_id, m0, 32);
    scalar_t id_bytes;
    blst_lendian_from_scalar(id_bytes, &s_id);
    g1_point_t h0_id;
    g1_mul(&h0_id, &params->hs[0], id_bytes);
    g1_point_t temp;
    g1_add(&temp, &C, &h0_id);
    C = temp;
    
    // C += M_1 (already contains h_1^{sk_u})
    g1_add(&temp, &C, M1);
    C = temp;
    
    // C += h_2^{exp}
    blst_scalar s_exp;
    blst_scalar_from_be_bytes(&s_exp, m2, 32);
    scalar_t exp_bytes;
    blst_lendian_from_scalar(exp_bytes, &s_exp);
    g1_point_t h2_exp;
    g1_mul(&h2_exp, &params->hs[2], exp_bytes);
    g1_add(&temp, &C, &h2_exp);
    C = temp;
    
    // C += ∏_{i=3}^l h_i^{m_i}
    for (size_t i = 0; i < user_attrs_len && (i + 3) <= params->max_attrs; i++) {
        g1_point_t term;
        blst_scalar s_attr;
        blst_scalar_from_be_bytes(&s_attr, user_attrs[i], 32);
        scalar_t attr_bytes;
        blst_lendian_from_scalar(attr_bytes, &s_attr);
        g1_mul(&term, &params->hs[i + 3], attr_bytes);
        g1_add(&temp, &C, &term);
        C = temp;
    }
    
    // Step 7: Generate signature (A, e)
    // e should be randomly selected from mod r (order of G1 in BLS12-381), not by hashing C
    // Need to ensure x + e != 0 (mod r)
    const int MAX_E_ATTEMPTS = 100;  // Maximum number of attempts
    blst_scalar s_e;
    blst_fr fr_x, fr_e, fr_sum;
    blst_scalar s_x;
    blst_scalar_from_be_bytes(&s_x, issuer_keys->x, 32);
    blst_fr_from_scalar(&fr_x, &s_x);
    
    bool found_valid_e = false;
    for (int attempt = 0; attempt < MAX_E_ATTEMPTS; attempt++) {
        // Randomly generate e (in mod r space, ensure not zero)
        random_scalar_mod_r(cert->e);
        
        // Convert to blst_scalar
        blst_scalar_from_be_bytes(&s_e, cert->e, 32);
        blst_fr_from_scalar(&fr_e, &s_e);
        
        // Check x + e != 0 (mod r)
        blst_fr_add(&fr_sum, &fr_x, &fr_e);
        
        // Use helper function to check if zero (check all data)
        if (!fr_is_zero(&fr_sum)) {
            found_valid_e = true;
            break;
        }
    }
    
    if (!found_valid_e) {
        return false;  // Cannot find valid e
    }
    
    // Compute A = C^{1/(x+e)}
    blst_fr fr_inv;
    blst_fr_inverse(&fr_inv, &fr_sum);
    
    blst_scalar s_inv;
    blst_scalar_from_fr(&s_inv, &fr_inv);
    scalar_t inv;
    blst_lendian_from_scalar(inv, &s_inv);
    g1_mul(&cert->A, &C, inv);
    
    // Construct complete attribute vector m = [m0=id, m1=sk_u, m2=exp, m3..ml=user_attrs]
    // Note: We cannot directly include sk_u here because it is secret
    // In actual applications, users need to store sk_u themselves
    cert->attr_count = user_attrs_len + 3;  // id, sk_u(placeholder), exp, user_attrs
    memcpy(cert->m[0], m0, 32);  // id
    memset(cert->m[1], 0, 32);   // sk_u placeholder (actual value stored by user)
    memcpy(cert->m[2], m2, 32);  // exp
    memcpy(cert->m + 3, user_attrs, user_attrs_len * 32);  // user_attrs
    
    return true;
}

// User-side certificate verification (Phase 3: Verification)
// According to paper algorithm, user verifies if signature (A, e) is correct
bool user_verify_certificate(const system_params_t *params, const certificate_t *cert,
                             const scalar_t sk_u) {
    // Step 9: Construct complete attribute vector
    // Note: cert->m[1] is placeholder, need to use actual sk_u
    if (!params || !cert) {
        return false;
    }
    
    // Verify attribute count
    if (cert->attr_count == 0 || cert->attr_count > MAX_ATTRS) {
        return false;
    }
    
    // Step 10: Verify signature
    // Compute C' = g_1 * h_0^{id} * h_1^{sk_u} * h_2^{exp} * ∏_{i=3}^l h_i^{m_i}
    g1_point_t C_prime = params->g1;  // C' = g_1
    
    // C' += h_0^{id}
    blst_scalar s_id;
    blst_scalar_from_be_bytes(&s_id, cert->m[0], 32);
    scalar_t id_bytes;
    blst_lendian_from_scalar(id_bytes, &s_id);
    g1_point_t h0_id;
    g1_mul(&h0_id, &params->hs[0], id_bytes);
    g1_point_t temp;
    g1_add(&temp, &C_prime, &h0_id);
    C_prime = temp;
    
    // C' += h_1^{sk_u}
    blst_scalar s_sk_u;
    blst_scalar_from_be_bytes(&s_sk_u, sk_u, 32);
    scalar_t sk_u_bytes;
    blst_lendian_from_scalar(sk_u_bytes, &s_sk_u);
    g1_point_t h1_sk_u;
    g1_mul(&h1_sk_u, &params->hs[1], sk_u_bytes);
    g1_add(&temp, &C_prime, &h1_sk_u);
    C_prime = temp;
    
    // C' += h_2^{exp}
    if (cert->attr_count > 2) {
        blst_scalar s_exp;
        blst_scalar_from_be_bytes(&s_exp, cert->m[2], 32);
        scalar_t exp_bytes;
        blst_lendian_from_scalar(exp_bytes, &s_exp);
        g1_point_t h2_exp;
        g1_mul(&h2_exp, &params->hs[2], exp_bytes);
        g1_add(&temp, &C_prime, &h2_exp);
        C_prime = temp;
    }
    
    // C' += ∏_{i=3}^l h_i^{m_i}
    for (size_t i = 3; i < cert->attr_count && i <= params->max_attrs; i++) {
        g1_point_t term;
        blst_scalar s_mi;
        blst_scalar_from_be_bytes(&s_mi, cert->m[i], 32);
        scalar_t mi_bytes;
        blst_lendian_from_scalar(mi_bytes, &s_mi);
        g1_mul(&term, &params->hs[i], mi_bytes);
        g1_add(&temp, &C_prime, &term);
        C_prime = temp;
    }
    
    // Verify e(A, X2 * g2^e) == e(C', g2)
    blst_scalar s_e;
    blst_scalar_from_be_bytes(&s_e, cert->e, 32);
    if (!blst_scalar_fr_check(&s_e)) {
        return false;
    }
    if (scalar_is_zero(cert->e)) {
        return false;
    }
    
    g2_point_t e_g2, X2_e;
    scalar_t e_bytes;
    blst_lendian_from_scalar(e_bytes, &s_e);
    g2_mul(&e_g2, &params->g2, e_bytes);
    g2_add(&X2_e, &params->X2, &e_g2);
    
    bool result = pairing_check(&cert->A, &X2_e, &C_prime, &params->g2);
    
    return result;
}

// Revoke certificate (when id is known)
// Note: issuer_keys is not const, because revoke_id needs to modify pending_revokes and pending_count
void revoke(system_params_t *params, issuer_keys_t *issuer_keys, const certificate_t *cert) {
    scalar_t id;
    memcpy(id, cert->m[0], 32);
    revoke_id(params, issuer_keys, id);
}

// Recover identifier from presentation transcript (according to paper algorithm)
// According to paper: If verifier observes malicious behavior, can submit presentation transcript (including g_r and g_2') to issuer
// After issuer verifies proof, recover identifier by checking if each candidate id satisfies g_2' == g_r^{id}
// Note: Need to access issued_ids in issuer_keys (confidential information)
bool recover_identifier_from_presentation(const system_params_t *params,
                                         const issuer_keys_t *issuer_keys,
                                         const g2_point_t *g_r, const g2_point_t *g2_p,
                                         scalar_t recovered_id) {
    if (!params || !issuer_keys || !g_r || !g2_p || !recovered_id) {
        return false;
    }
    
    // Check if there are issued IDs (in issuer_keys)
    if (!issuer_keys->issued_ids || issuer_keys->issued_count == 0) {
        return false;
    }
    
    // Iterate through all issued IDs, check g_2' == g_r^{id}
    for (size_t i = 0; i < issuer_keys->issued_count; i++) {
        // issued_ids now directly stores scalar_t, no conversion needed
        scalar_t candidate_id;
        memcpy(candidate_id, issuer_keys->issued_ids[i], 32);
        
        // Compute g_r^{candidate_id}
        blst_scalar s_candidate_id;
        blst_scalar_from_be_bytes(&s_candidate_id, candidate_id, 32);
        scalar_t candidate_id_bytes;
        blst_lendian_from_scalar(candidate_id_bytes, &s_candidate_id);
        
        g2_point_t g_r_to_id;
        g2_mul(&g_r_to_id, g_r, candidate_id_bytes);
        
        // Check g_r^{candidate_id} == g_2'
        // Compare two G2 points by serialization
        byte g_r_to_id_bytes[192], g2_p_bytes[192];
        blst_p2_serialize(g_r_to_id_bytes, &g_r_to_id);
        blst_p2_serialize(g2_p_bytes, g2_p);
        
        if (memcmp(g_r_to_id_bytes, g2_p_bytes, 192) == 0) {
            // Found matching ID
            memcpy(recovered_id, candidate_id, 32);
            return true;
        }
    }
    
    // No matching ID found
    return false;
}

