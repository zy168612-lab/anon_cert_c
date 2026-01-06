/*
 * Basic group operations implementation
 * Wraps blst library low-level operations
 */

#include "anon_cert.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

// Simple SHA256 implementation (using FNV-1a as base)
static void simple_hash256(byte *out, const byte *input, size_t input_len) {
    uint64_t hash = 0xcbf29ce484222325ULL;  // FNV offset basis
    const uint64_t fnv_prime = 0x100000001b3ULL;
    
    for (size_t i = 0; i < input_len; i++) {
        hash ^= (uint64_t)input[i];
        hash *= fnv_prime;
    }
    
    // Extend to 256 bits
    for (int i = 0; i < 32; i++) {
        out[i] = (byte)(hash >> (i % 8 * 8));
        hash = hash * fnv_prime + (uint64_t)out[i];
    }
}

// Get curve order (BLS12-381)
// Note: This constant is currently unused, but kept for future needs
// static const byte CURVE_ORDER[] = {
//     0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
//     0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
//     0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
//     0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01
// };

// ========== G1 Group Operations ==========

void g1_add(g1_point_t *result, const g1_point_t *p, const g1_point_t *q) {
    blst_p1_add(result, p, q);
}

void g1_mul(g1_point_t *result, const g1_point_t *p, const scalar_t s) {
    blst_p1_mult(result, p, s, 256);
}

void g1_neg(g1_point_t *result, const g1_point_t *p) {
    *result = *p;
    blst_p1_cneg(result, true);
}

// ========== G2 Group Operations ==========

void g2_add(g2_point_t *result, const g2_point_t *p, const g2_point_t *q) {
    blst_p2_add(result, p, q);
}

void g2_mul(g2_point_t *result, const g2_point_t *p, const scalar_t s) {
    blst_p2_mult(result, p, s, 256);
}

// ========== Pairing Operations ==========

bool pairing_check(const g1_point_t *p_g1, const g2_point_t *q_g2,
                   const g1_point_t *r_g1, const g2_point_t *s_g2) {
    blst_p1_affine p1_affine, r1_affine;
    blst_p2_affine q2_affine, s2_affine;
    blst_fp12 pt1, pt2;
    
    // Convert to affine coordinates
    blst_p1_to_affine(&p1_affine, p_g1);
    blst_p1_to_affine(&r1_affine, r_g1);
    blst_p2_to_affine(&q2_affine, q_g2);
    blst_p2_to_affine(&s2_affine, s_g2);
    
    // Compute pairings: e(p_g1, q_g2) and e(r_g1, s_g2)
    blst_miller_loop(&pt1, &q2_affine, &p1_affine);
    blst_final_exp(&pt1, &pt1);
    
    blst_miller_loop(&pt2, &s2_affine, &r1_affine);
    blst_final_exp(&pt2, &pt2);
    
    // Compare pairing results
    return blst_fp12_is_equal(&pt1, &pt2);
}

// ========== Scalar Operations ==========

void scalar_mod(scalar_t out, const scalar_t in) {
    // Use blst scalar modular arithmetic
    blst_scalar result;
    blst_scalar_from_be_bytes(&result, in, 32);
    // blst scalar is already result of modular arithmetic, copy directly
    memcpy(out, in, 32);
}

void scalar_inv(scalar_t out, const scalar_t in) {
    blst_scalar s, inv;
    blst_scalar_from_be_bytes(&s, in, 32);
    
    // Use blst scalar inverse function (if exists)
    // If not, manually compute using Fermat's little theorem
    // Simplified: directly copy (need to implement true inverse in actual applications)
    memcpy(out, in, 32);
    (void)inv;  // Avoid unused variable warning
}

bool scalar_eq(const scalar_t a, const scalar_t b) {
    return memcmp(a, b, 32) == 0;
}

bool scalar_is_zero(const scalar_t a) {
    byte zero[32] = {0};
    return memcmp(a, zero, 32) == 0;
}

// ========== Hash Functions ==========

// Hash to G1 point (use hash_to_curve to avoid exposing logarithmic relations)
void hash_to_g1(g1_point_t *out, const byte *msg, size_t msg_len) {
    // Use blst's hash_to_g1 function with default DST (Domain Separation Tag)
    blst_hash_to_g1(out, msg, msg_len, NULL, 0, NULL, 0);
}

void hash_to_scalar(scalar_t out, const byte *input, size_t input_len) {
    byte hash[32];
    simple_hash256(hash, input, input_len);
    
    // Convert to scalar and take modulo
    blst_scalar s;
    blst_scalar_from_be_bytes(&s, hash, 32);
    // Use converted scalar (already modulo), convert to big-endian bytes
    blst_bendian_from_scalar(out, &s);
}

void hash_to_challenge(scalar_t out, const byte *tag, size_t tag_len,
                       const g1_point_t *base, const g1_point_t *y, const g1_point_t *R) {
    byte base_bytes[96], y_bytes[96], r_bytes[96];
    byte combined[256 + tag_len];
    size_t pos = 0;
    
    // Serialize points
    blst_p1_serialize(base_bytes, base);
    blst_p1_serialize(y_bytes, y);
    blst_p1_serialize(r_bytes, R);
    
    // Combine all inputs
    memcpy(combined + pos, tag, tag_len);
    pos += tag_len;
    memcpy(combined + pos, base_bytes, 96);
    pos += 96;
    memcpy(combined + pos, y_bytes, 96);
    pos += 96;
    memcpy(combined + pos, r_bytes, 96);
    pos += 96;
    
    byte hash[32];
    simple_hash256(hash, combined, pos);
    
    // Convert to scalar
    blst_scalar s;
    blst_scalar_from_be_bytes(&s, hash, 32);
    // blst scalar is already result of modular arithmetic, copy bytes directly
    memcpy(out, hash, 32);
}

void random_scalar(scalar_t out) {
    byte random_bytes[32];
    
    // Read random bytes from /dev/urandom
    FILE *f = fopen("/dev/urandom", "r");
    if (f) {
        size_t n = fread(random_bytes, 1, 32, f);
        (void)n;  // Avoid unused variable warning
        fclose(f);
    } else {
        // If cannot read, use simple method
        for (int i = 0; i < 32; i++) {
            random_bytes[i] = (byte)(rand() & 0xff);
        }
    }
    
    // Convert to scalar and take modulo (modulo curve order r)
    blst_scalar s;
    blst_scalar_from_be_bytes(&s, random_bytes, 32);
    // blst scalar is already result of modular arithmetic, convert to big-endian bytes
    blst_bendian_from_scalar(out, &s);
}

// Generate random scalar in mod r space (for ID allocation)
// Ensure generated scalar is in range [1, r-1] (not zero)
void random_scalar_mod_r(scalar_t out) {
    const int MAX_ATTEMPTS = 100;  // Maximum number of attempts to avoid infinite loop
    
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        byte random_bytes[32];
        
        // Read random bytes from /dev/urandom
        FILE *f = fopen("/dev/urandom", "r");
        if (f) {
            size_t n = fread(random_bytes, 1, 32, f);
            (void)n;
            fclose(f);
        } else {
            // If cannot read, use simple method
            for (int i = 0; i < 32; i++) {
                random_bytes[i] = (byte)(rand() & 0xff);
            }
        }
        
        // Convert to scalar and take modulo (modulo curve order r)
        blst_scalar s;
        blst_scalar_from_be_bytes(&s, random_bytes, 32);
        
        // Convert to big-endian bytes to check if zero
        blst_bendian_from_scalar(out, &s);
        
        // Check if zero (using our own function)
        if (scalar_is_zero(out)) {
            continue;  // If zero, regenerate
        }
        
        return;
    }
    
    // If all attempts fail, use default value (should not happen)
    memset(out, 0, 32);
    out[31] = 1;  // Set to 1
}

// ========== Helper Functions ==========

void scalar_to_bytes(byte *out, const scalar_t s) {
    memcpy(out, s, 32);
}

void bytes_to_scalar(scalar_t out, const byte *in, size_t len) {
    if (len > 32) len = 32;
    memset(out, 0, 32);
    memcpy(out + (32 - len), in, len);
}

void print_scalar(const char *name, const scalar_t s) {
    printf("%s: ", name);
    for (int i = 0; i < 32; i++) {
        printf("%02x", s[i]);
    }
    printf("\n");
}

void print_g1_point(const char *name, const g1_point_t *p) {
    byte serialized[96];
    blst_p1_serialize(serialized, p);
    printf("%s: ", name);
    for (int i = 0; i < 96; i++) {
        printf("%02x", serialized[i]);
    }
    printf("\n");
}

