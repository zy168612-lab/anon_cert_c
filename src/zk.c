/*
 * Schnorr zero-knowledge proof implementation
 */

#include "anon_cert.h"
#include <string.h>
#include <stdlib.h>

// Generate Schnorr proof
// If r_commit is not NULL, use that value as commitment random number; otherwise generate new random number
void schnorr_prove(schnorr_proof_t *proof, const g1_point_t *base,
                   const g1_point_t *y, const scalar_t w, const byte *tag, size_t tag_len,
                   const scalar_t *r_commit) {
    // If r_commit is provided, use it; otherwise generate random r
    scalar_t r;
    if (r_commit != NULL) {
        memcpy(r, r_commit, 32);
    } else {
        random_scalar(r);
    }
    
    // R = r * base
    // r is big-endian, need to convert to little-endian
    blst_scalar s_r_prove;
    blst_scalar_from_be_bytes(&s_r_prove, r, 32);
    scalar_t r_bytes;
    blst_lendian_from_scalar(r_bytes, &s_r_prove);
    g1_mul(&proof->R, base, r_bytes);
    
    // c = hash(tag, base, y, R)
    hash_to_challenge(proof->s, tag, tag_len, base, y, &proof->R);
    scalar_t c;
    memcpy(c, proof->s, 32);  // Temporarily store c
    
    // s = r + c * w
    blst_scalar s_r, s_c, s_w;
    blst_scalar_from_be_bytes(&s_r, r, 32);
    blst_scalar_from_be_bytes(&s_c, c, 32);
    blst_scalar_from_be_bytes(&s_w, w, 32);
    
    blst_fr fr_r, fr_c, fr_w, fr_cw, fr_result;
    blst_fr_from_scalar(&fr_r, &s_r);
    blst_fr_from_scalar(&fr_c, &s_c);
    blst_fr_from_scalar(&fr_w, &s_w);
    
    blst_fr_mul(&fr_cw, &fr_c, &fr_w);
    blst_fr_add(&fr_result, &fr_r, &fr_cw);
    
    blst_scalar s_result;
    blst_scalar_from_fr(&s_result, &fr_result);
    blst_bendian_from_scalar(proof->s, &s_result);
}

// Verify Schnorr proof
bool schnorr_verify(const g1_point_t *base, const g1_point_t *y,
                    const schnorr_proof_t *proof, const byte *tag, size_t tag_len) {
    // Compute challenge c
    scalar_t c;
    hash_to_challenge(c, tag, tag_len, base, y, &proof->R);
    
    // Check s*base == R + c*y
    // proof->s and c are big-endian, need to convert to little-endian
    blst_scalar s_s, s_c;
    blst_scalar_from_be_bytes(&s_s, proof->s, 32);
    blst_scalar_from_be_bytes(&s_c, c, 32);
    scalar_t s_bytes, c_bytes;
    blst_lendian_from_scalar(s_bytes, &s_s);
    blst_lendian_from_scalar(c_bytes, &s_c);
    
    g1_point_t left, right, cy;
    g1_mul(&left, base, s_bytes);
    g1_mul(&cy, y, c_bytes);
    g1_add(&right, &proof->R, &cy);
    
    // Compare points
    byte left_bytes[96], right_bytes[96];
    blst_p1_serialize(left_bytes, &left);
    blst_p1_serialize(right_bytes, &right);
    
    return memcmp(left_bytes, right_bytes, 96) == 0;
}

// Batch Schnorr proof: prove multiple relations all use same secret value r
// All proofs share same challenge value, thus proving they use same r
void schnorr_batch_prove(schnorr_proof_t *proofs, const g1_point_t *bases,
                         const g1_point_t *ys, const scalar_t *ws, size_t count,
                         const byte *tag, size_t tag_len, const scalar_t r_commit,
                         scalar_t out_c) {
    // Step 1: Generate all commitments R_i = r_commit * base_i
    blst_scalar s_r;
    blst_scalar_from_be_bytes(&s_r, r_commit, 32);
    scalar_t r_bytes;
    blst_lendian_from_scalar(r_bytes, &s_r);
    
    for (size_t i = 0; i < count; i++) {
        g1_mul(&proofs[i].R, &bases[i], r_bytes);
    }
    
    // Step 2: Compute unified challenge value c = hash(tag, base_1, y_1, R_1, ..., base_n, y_n, R_n)
    // Combine all inputs
    size_t combined_size = tag_len + count * (96 + 96 + 96);  // tag + (base + y + R) for each
    byte *combined = (byte *)malloc(combined_size);
    if (!combined) {
        return;  // Memory allocation failed
    }
    
    size_t pos = 0;
    memcpy(combined + pos, tag, tag_len);
    pos += tag_len;
    
    for (size_t i = 0; i < count; i++) {
        byte base_bytes[96], y_bytes[96], r_bytes_ser[96];
        blst_p1_serialize(base_bytes, &bases[i]);
        blst_p1_serialize(y_bytes, &ys[i]);
        blst_p1_serialize(r_bytes_ser, &proofs[i].R);
        
        memcpy(combined + pos, base_bytes, 96);
        pos += 96;
        memcpy(combined + pos, y_bytes, 96);
        pos += 96;
        memcpy(combined + pos, r_bytes_ser, 96);
        pos += 96;
    }
    
    // Compute challenge value
    hash_to_scalar(out_c, combined, combined_size);
    free(combined);
    
    // Step 3: Compute response s_i = r_commit + c * w_i
    blst_scalar s_c;
    blst_scalar_from_be_bytes(&s_c, out_c, 32);
    blst_fr fr_r, fr_c;
    blst_fr_from_scalar(&fr_r, &s_r);
    blst_fr_from_scalar(&fr_c, &s_c);
    
    for (size_t i = 0; i < count; i++) {
        blst_scalar s_w;
        blst_scalar_from_be_bytes(&s_w, ws[i], 32);
        blst_fr fr_w, fr_cw, fr_result;
        blst_fr_from_scalar(&fr_w, &s_w);
        
        blst_fr_mul(&fr_cw, &fr_c, &fr_w);
        blst_fr_add(&fr_result, &fr_r, &fr_cw);
        
        blst_scalar s_result;
        blst_scalar_from_fr(&s_result, &fr_result);
        blst_bendian_from_scalar(proofs[i].s, &s_result);
    }
}

// Verify batch Schnorr proof
bool schnorr_batch_verify(const g1_point_t *bases, const g1_point_t *ys,
                          const schnorr_proof_t *proofs, size_t count,
                          const byte *tag, size_t tag_len, const scalar_t c) {
    // Step 1: Recompute unified challenge value
    size_t combined_size = tag_len + count * (96 + 96 + 96);
    byte *combined = (byte *)malloc(combined_size);
    if (!combined) {
        return false;
    }
    
    size_t pos = 0;
    memcpy(combined + pos, tag, tag_len);
    pos += tag_len;
    
    for (size_t i = 0; i < count; i++) {
        byte base_bytes[96], y_bytes[96], r_bytes[96];
        blst_p1_serialize(base_bytes, &bases[i]);
        blst_p1_serialize(y_bytes, &ys[i]);
        blst_p1_serialize(r_bytes, &proofs[i].R);
        
        memcpy(combined + pos, base_bytes, 96);
        pos += 96;
        memcpy(combined + pos, y_bytes, 96);
        pos += 96;
        memcpy(combined + pos, r_bytes, 96);
        pos += 96;
    }
    
    scalar_t computed_c;
    hash_to_scalar(computed_c, combined, combined_size);
    free(combined);
    
    // Check if challenge values match
    if (memcmp(computed_c, c, 32) != 0) {
        return false;  // Challenge values do not match
    }
    
    // Step 2: Verify each proof s_i * base_i == R_i + c * y_i
    blst_scalar s_c;
    blst_scalar_from_be_bytes(&s_c, c, 32);
    scalar_t c_bytes;
    blst_lendian_from_scalar(c_bytes, &s_c);
    
    for (size_t i = 0; i < count; i++) {
        blst_scalar s_s;
        blst_scalar_from_be_bytes(&s_s, proofs[i].s, 32);
        scalar_t s_bytes;
        blst_lendian_from_scalar(s_bytes, &s_s);
        
        g1_point_t left, right, cy;
        g1_mul(&left, &bases[i], s_bytes);
        g1_mul(&cy, &ys[i], c_bytes);
        g1_add(&right, &proofs[i].R, &cy);
        
        byte left_bytes[96], right_bytes[96];
        blst_p1_serialize(left_bytes, &left);
        blst_p1_serialize(right_bytes, &right);
        
        if (memcmp(left_bytes, right_bytes, 96) != 0) {
            return false;
        }
    }
    
    return true;
}

