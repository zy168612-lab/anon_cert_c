/*
 * Accumulator functionality implementation
 */

#include "anon_cert.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>

// Get current time (microseconds) - for performance measurement
static double get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000.0 + tv.tv_usec;
}

// Initialize accumulator
void setup_accumulator(system_params_t *params, issuer_keys_t *issuer_keys, size_t q) {
    params->q = q;
    // Fixed batch revocation size, default follows document recommendation of at least 5
    params->rev_batch_size = 5;
    
    // Initialize pending_revokes in issuer_keys (confidential information)
    issuer_keys->pending_count = 0;
    issuer_keys->pending_revokes = NULL;
    // Need q+1 elements (including i=0), but allocate more initially to support dynamic growth
    // Number of revoked IDs may exceed q, so need to reserve more space
    // Initial capacity set to q+1, but can be expanded as needed
    params->q_capacity = q + 1;  // Need q+1 elements (including i=0)
    
    // Dynamically allocate g1_kappa_powers
    params->g1_kappa_powers = (g1_point_t *)malloc(params->q_capacity * sizeof(g1_point_t));
    if (!params->g1_kappa_powers) {
        return;
    }
    
    // Generate kappa (using hash, only issuer holds)
    byte kappa_seed[] = "acc_kappa";
    hash_to_scalar(issuer_keys->kappa, kappa_seed, sizeof(kappa_seed) - 1);
    
    // Compute g2^{kappa}
    // issuer_keys->kappa is big-endian, need to convert to little-endian
    blst_scalar s_kappa;
    blst_scalar_from_be_bytes(&s_kappa, issuer_keys->kappa, 32);
    scalar_t kappa_bytes;
    blst_lendian_from_scalar(kappa_bytes, &s_kappa);
    g2_mul(&params->g2_kappa, &params->g2, kappa_bytes);
    
    // Compute g1^{kappa^i} for i = 0..q
    scalar_t one = {0};
    one[31] = 1;  // Scalar 1
    blst_scalar s_one;
    blst_scalar_from_be_bytes(&s_one, one, 32);
    scalar_t one_bytes;
    blst_lendian_from_scalar(one_bytes, &s_one);
    g1_mul(&params->g1_kappa_powers[0], &params->g1, one_bytes);
    
    // Reuse previously declared kappa_bytes
    // Compute g1^{kappa^i} for i = 1..q
    for (size_t i = 1; i <= q; i++) {
        // Compute kappa^i (simplified: using scalar multiplication)
        // Note: Need to implement scalar multiplication here, temporarily using simplified method
        g1_mul(&params->g1_kappa_powers[i], &params->g1_kappa_powers[i-1], kappa_bytes);
    }
    
    // Note: If number of revoked IDs exceeds q, need to expand g1_kappa_powers in revoke_id
    // But keep it simple for now, assume revocation count won't exceed q
    
    // Initialize revocation state (dynamically allocated)
    // Store polynomial coefficients per batch, not revoked IDs
    params->batch_capacity = q / params->rev_batch_size + 1;  // Initial capacity
    params->batch_poly_coeffs = (scalar_t **)malloc(params->batch_capacity * sizeof(scalar_t *));
    params->batch_poly_counts = (size_t *)malloc(params->batch_capacity * sizeof(size_t));
    params->batch_count = 0;
    
    if (!params->batch_poly_coeffs || !params->batch_poly_counts) {
        cleanup_accumulator(params);
        return;
    }
    
    params->accum_capacity = q;  // Initial capacity set to q
    params->accum_values = (g1_point_t *)malloc(params->accum_capacity * sizeof(g1_point_t));
    params->accum_count = 0;
    
    // Initialize total polynomial (initially constant polynomial 1)
    params->total_poly_capacity = 1;
    params->total_poly_coeffs = (scalar_t *)malloc(params->total_poly_capacity * sizeof(scalar_t));
    if (params->total_poly_coeffs) {
        memset(params->total_poly_coeffs[0], 0, 32);
        params->total_poly_coeffs[0][31] = 1;  // Constant polynomial 1
        params->total_poly_count = 1;
    } else {
        params->total_poly_count = 0;
        params->total_poly_capacity = 0;
    }
    
    // Initialize ID allocation (dynamically allocated, in issuer_keys, confidential information)
    issuer_keys->issued_capacity = q;  // Initial capacity set to q
    issuer_keys->issued_ids = (scalar_t *)malloc(issuer_keys->issued_capacity * sizeof(scalar_t));
    issuer_keys->issued_count = 0;
    
    // Initialize fixed batch temporary storage (in issuer_keys, confidential information)
    issuer_keys->pending_revokes = (scalar_t *)malloc(params->rev_batch_size * sizeof(scalar_t));
    issuer_keys->pending_count = 0;
    
    if (!params->accum_values || !params->total_poly_coeffs || !issuer_keys->issued_ids || !issuer_keys->pending_revokes) {
        cleanup_accumulator(params);
        // Cleanup resources in issuer_keys
        if (issuer_keys->pending_revokes) {
            free(issuer_keys->pending_revokes);
            issuer_keys->pending_revokes = NULL;
        }
        if (issuer_keys->issued_ids) {
            free(issuer_keys->issued_ids);
            issuer_keys->issued_ids = NULL;
        }
        return;
    }
}

// Cleanup accumulator resources
void cleanup_accumulator(system_params_t *params) {
    if (params->g1_kappa_powers) {
        free(params->g1_kappa_powers);
        params->g1_kappa_powers = NULL;
    }
    // Cleanup polynomial coefficients per batch
    if (params->batch_poly_coeffs) {
        for (size_t i = 0; i < params->batch_count; i++) {
            if (params->batch_poly_coeffs[i]) {
                free(params->batch_poly_coeffs[i]);
            }
        }
        free(params->batch_poly_coeffs);
        params->batch_poly_coeffs = NULL;
    }
    if (params->batch_poly_counts) {
        free(params->batch_poly_counts);
        params->batch_poly_counts = NULL;
    }
    if (params->accum_values) {
        free(params->accum_values);
        params->accum_values = NULL;
    }
    if (params->total_poly_coeffs) {
        free(params->total_poly_coeffs);
        params->total_poly_coeffs = NULL;
    }
    // Note: pending_revokes and issued_ids are now in issuer_keys (confidential information), not in params
    // Cleanup function only handles resources in params, issuer_keys resources need separate cleanup
    params->q_capacity = 0;
    params->batch_capacity = 0;
    params->total_poly_count = 0;
    params->total_poly_capacity = 0;
    params->batch_count = 0;
    params->accum_capacity = 0;
}

// Forward declaration: polynomial utilities
static void poly_from_roots(scalar_t *coeffs, size_t *coeff_count,
                             const scalar_t *roots, size_t root_count);
static void poly_eval(scalar_t result, const scalar_t *coeffs, size_t coeff_count, const scalar_t x);

// Forward declaration
static bool compute_total_poly_internal(scalar_t *f_coeffs, size_t *f_count,
                                       const system_params_t *params);

// Revoke ID (automatically expand capacity, fixed batch processing)
void revoke_id(system_params_t *params, issuer_keys_t *issuer_keys, const scalar_t id) {
    // Update accumulator after collecting to fixed batch
    // Note: pending_revokes is now in issuer_keys (confidential information)
    memcpy(issuer_keys->pending_revokes[issuer_keys->pending_count], id, 32);
    issuer_keys->pending_count++;
    
    // Batch not full, don't perform update
    if (issuer_keys->pending_count < params->rev_batch_size) {
        return;
    }
    
    // Compute current batch polynomial f_t(X)=Π (X+id_r)
    scalar_t *f_coeffs = (scalar_t *)malloc((params->rev_batch_size + 1) * sizeof(scalar_t));
    if (!f_coeffs) {
        issuer_keys->pending_count = 0;
        return;
    }
    size_t f_count = 0;
    poly_from_roots(f_coeffs, &f_count, issuer_keys->pending_revokes, params->rev_batch_size);
    
    // Store current batch polynomial coefficients (public parameter)
    // If batch capacity insufficient, expand memory
    if (params->batch_count >= params->batch_capacity) {
        size_t new_capacity = params->batch_capacity * 2;
        if (new_capacity < params->batch_capacity + 1) {
            new_capacity = params->batch_capacity + 1;
        }
        scalar_t **new_batch_poly_coeffs = (scalar_t **)realloc(params->batch_poly_coeffs, new_capacity * sizeof(scalar_t *));
        size_t *new_batch_poly_counts = (size_t *)realloc(params->batch_poly_counts, new_capacity * sizeof(size_t));
        if (!new_batch_poly_coeffs || !new_batch_poly_counts) {
            free(f_coeffs);
            issuer_keys->pending_count = 0;
            return;
        }
        params->batch_poly_coeffs = new_batch_poly_coeffs;
        params->batch_poly_counts = new_batch_poly_counts;
        params->batch_capacity = new_capacity;
    }
    
    // Allocate and store current batch polynomial coefficients
    params->batch_poly_coeffs[params->batch_count] = (scalar_t *)malloc(f_count * sizeof(scalar_t));
    if (!params->batch_poly_coeffs[params->batch_count]) {
        free(f_coeffs);
        issuer_keys->pending_count = 0;
        return;
    }
    memcpy(params->batch_poly_coeffs[params->batch_count], f_coeffs, f_count * sizeof(scalar_t));
    params->batch_poly_counts[params->batch_count] = f_count;
    params->batch_count++;
    
    // Compute total revocation count (to determine if need to expand g1_kappa_powers)
    size_t total_revoked_count = params->batch_count * params->rev_batch_size;
    
    // If revocation count exceeds q, need to expand g1_kappa_powers
    // Because non-membership proof may need to compute higher powers of kappa
    if (total_revoked_count > params->q) {
        size_t needed_capacity = total_revoked_count + 1;  // Need total_revoked_count + 1 elements
        if (needed_capacity > params->q_capacity) {
            size_t new_q_capacity = needed_capacity;
            g1_point_t *new_g1_kappa_powers = (g1_point_t *)realloc(params->g1_kappa_powers, new_q_capacity * sizeof(g1_point_t));
            if (!new_g1_kappa_powers) {
                free(f_coeffs);
                issuer_keys->pending_count = 0;
                return;
            }
            params->g1_kappa_powers = new_g1_kappa_powers;
            
            // Compute additional kappa powers
            blst_scalar s_kappa;
            blst_scalar_from_be_bytes(&s_kappa, issuer_keys->kappa, 32);
            scalar_t kappa_bytes;
            blst_lendian_from_scalar(kappa_bytes, &s_kappa);
            
            for (size_t i = params->q_capacity; i < new_q_capacity; i++) {
                g1_mul(&params->g1_kappa_powers[i], &params->g1_kappa_powers[i-1], kappa_bytes);
            }
            params->q_capacity = new_q_capacity;
        }
    }
    
    // Compute f_t(kappa)
    scalar_t f_kappa;
    blst_scalar s_kappa;
    blst_scalar_from_be_bytes(&s_kappa, issuer_keys->kappa, 32);
    scalar_t kappa_be;
    blst_bendian_from_scalar(kappa_be, &s_kappa);
    poly_eval(f_kappa, f_coeffs, f_count, kappa_be);
    
    // Update accumulator value with f_kappa as exponent: A_t = A_{t-1}^{f_t(kappa)}
    // If capacity insufficient, expand memory
    if (params->accum_count >= params->accum_capacity) {
        size_t new_capacity = params->accum_capacity * 2;
        if (new_capacity < params->accum_capacity + 1) {
            new_capacity = params->accum_capacity + 1;
        }
        g1_point_t *new_accum_values = (g1_point_t *)realloc(params->accum_values, new_capacity * sizeof(g1_point_t));
        if (!new_accum_values) {
            free(f_coeffs);
            issuer_keys->pending_count = 0;
            return;
        }
        params->accum_values = new_accum_values;
        params->accum_capacity = new_capacity;
    }
    
    // f_kappa is big-endian, convert to little-endian for point multiplication
    blst_scalar s_fkappa;
    blst_scalar_from_be_bytes(&s_fkappa, f_kappa, 32);
    scalar_t fkappa_le;
    blst_lendian_from_scalar(fkappa_le, &s_fkappa);
    
    if (params->accum_count == 0) {
        // Initial accumulator value: A_1 = g1^{f_1(kappa)}
        g1_mul(&params->accum_values[0], &params->g1, fkappa_le);
        params->accum_count = 1;
    } else {
        g1_point_t last = params->accum_values[params->accum_count - 1];
        g1_mul(&params->accum_values[params->accum_count], &last, fkappa_le);
        params->accum_count++;
    }
    
    // Update total polynomial f_R(X) = ∏_{i=1}^t f_i(X) (synchronized with A_t)
    // Use incremental computation: f' = f * fi(X) mod p
    // Where f is current total_poly, fi(X) is new batch polynomial f_coeffs
    size_t new_total_poly_count;
    
    if (params->total_poly_count == 0 || !params->total_poly_coeffs) {
        // First time: directly use new batch polynomial
        new_total_poly_count = f_count;
        params->total_poly_capacity = new_total_poly_count;
        params->total_poly_coeffs = (scalar_t *)malloc(params->total_poly_capacity * sizeof(scalar_t));
        if (!params->total_poly_coeffs) {
            // Memory allocation failed, but accumulator already updated, continue execution
            issuer_keys->pending_count = 0;
            free(f_coeffs);
            return;
        }
        memcpy(params->total_poly_coeffs, f_coeffs, f_count * sizeof(scalar_t));
        params->total_poly_count = new_total_poly_count;
    } else {
        // Incremental computation: f' = f * fi(X)
        // Compute polynomial size after multiplication
        size_t expected_size = params->total_poly_count + f_count - 1;
        scalar_t *new_total_poly = (scalar_t *)malloc(expected_size * sizeof(scalar_t));
        if (!new_total_poly) {
            // Memory allocation failed, but accumulator already updated, continue execution
            issuer_keys->pending_count = 0;
            free(f_coeffs);
            return;
        }
        
        // Perform polynomial multiplication: new_total_poly = total_poly_coeffs * f_coeffs
        poly_mul(new_total_poly, &new_total_poly_count,
                 params->total_poly_coeffs, params->total_poly_count,
                 f_coeffs, f_count);
        
        // Free old total polynomial
        free(params->total_poly_coeffs);
        
        // Allocate sufficient space to store new total polynomial
        params->total_poly_capacity = new_total_poly_count;
        params->total_poly_coeffs = (scalar_t *)malloc(params->total_poly_capacity * sizeof(scalar_t));
        if (!params->total_poly_coeffs) {
            // Memory allocation failed, but accumulator already updated, continue execution
            free(new_total_poly);
            issuer_keys->pending_count = 0;
            free(f_coeffs);
            return;
        }
        
        memcpy(params->total_poly_coeffs, new_total_poly, new_total_poly_count * sizeof(scalar_t));
        params->total_poly_count = new_total_poly_count;
        free(new_total_poly);
    }
    
    // Clear current batch cache (in issuer_keys)
    issuer_keys->pending_count = 0;
    free(f_coeffs);
}

// Construct polynomial from roots (helper function)
static void poly_from_roots(scalar_t *coeffs, size_t *coeff_count,
                             const scalar_t *roots, size_t root_count) {
    // Initially constant polynomial 1
    memset(coeffs[0], 0, 32);
    coeffs[0][31] = 1;
    *coeff_count = 1;

    for (size_t i = 0; i < root_count; i++) {
        // Multiply by (X + root[i])
        scalar_t *new_coeffs = (scalar_t *)malloc((*coeff_count + 1) * sizeof(scalar_t));
        if (!new_coeffs) {
            return;
        }
        for (size_t j = 0; j <= *coeff_count; j++) {
            memset(new_coeffs[j], 0, 32);
        }

        // new_coeffs[j] = coeffs[j] * root + coeffs[j-1] (where coeffs[-1]=0)
        for (size_t j = 0; j < *coeff_count; j++) {
            blst_scalar s_coeff, s_root;
            blst_scalar_from_be_bytes(&s_coeff, coeffs[j], 32);
            blst_scalar_from_be_bytes(&s_root, roots[i], 32);

            blst_fr fr_coeff, fr_root, fr_prod;
            blst_fr_from_scalar(&fr_coeff, &s_coeff);
            blst_fr_from_scalar(&fr_root, &s_root);
            blst_fr_mul(&fr_prod, &fr_coeff, &fr_root);  // coeffs[j] * root

            // Add to constant term new_coeffs[j]
            blst_scalar s_new_const;
            blst_scalar_from_be_bytes(&s_new_const, new_coeffs[j], 32);
            blst_fr fr_new_const, fr_sum_const;
            blst_fr_from_scalar(&fr_new_const, &s_new_const);
            blst_fr_add(&fr_sum_const, &fr_new_const, &fr_prod);
            blst_scalar_from_fr(&s_new_const, &fr_sum_const);
            blst_bendian_from_scalar(new_coeffs[j], &s_new_const);

            // Copy coeffs[j] to X term new_coeffs[j+1] (accumulate)
            blst_scalar s_new_x;
            blst_scalar_from_be_bytes(&s_new_x, new_coeffs[j + 1], 32);
            blst_fr fr_new_x, fr_sum_x;
            blst_fr_from_scalar(&fr_new_x, &s_new_x);
            blst_fr_add(&fr_sum_x, &fr_new_x, &fr_coeff);
            blst_scalar_from_fr(&s_new_x, &fr_sum_x);
            blst_bendian_from_scalar(new_coeffs[j + 1], &s_new_x);
        }

        memcpy(coeffs, new_coeffs, (*coeff_count + 1) * 32);
        (*coeff_count)++;
        free(new_coeffs);
    }
}

// Polynomial evaluation (Horner's method)
static void poly_eval(scalar_t result, const scalar_t *coeffs, size_t coeff_count, const scalar_t x) {
    memset(result, 0, 32);
    
    for (int i = coeff_count - 1; i >= 0; i--) {
        // result = result * x + coeffs[i]
        blst_scalar s_result, s_x, s_coeff;
        blst_scalar_from_be_bytes(&s_result, result, 32);
        blst_scalar_from_be_bytes(&s_x, x, 32);
        blst_scalar_from_be_bytes(&s_coeff, coeffs[i], 32);
        
        blst_fr fr_result, fr_x, fr_coeff, fr_prod, fr_sum;
        blst_fr_from_scalar(&fr_result, &s_result);
        blst_fr_from_scalar(&fr_x, &s_x);
        blst_fr_from_scalar(&fr_coeff, &s_coeff);
        
        blst_fr_mul(&fr_prod, &fr_result, &fr_x);
        blst_fr_add(&fr_sum, &fr_prod, &fr_coeff);
        
        blst_scalar s_sum;
        blst_scalar_from_fr(&s_sum, &fr_sum);
        blst_bendian_from_scalar(result, &s_sum);
    }
}

// Polynomial division by linear factor (synthetic division)
static void poly_div_by_linear(scalar_t *quotient, size_t *quotient_count,
                                scalar_t *remainder, const scalar_t *coeffs, size_t coeff_count,
                                const scalar_t root) {
    // Synthetic division implementation for polynomial divided by (X + root).
    // coeffs represents f(x) = a_0 + a_1 x + ... + a_{n-1} x^{n-1}
    // Let alpha = -root, then f(x) = (x - alpha) q(x) + r
    // Here we compute coefficients of q and remainder r step by step.
    *quotient_count = coeff_count - 1;

    // Compute alpha = -root
    blst_scalar s_root;
    blst_scalar_from_be_bytes(&s_root, root, 32);

    blst_fr fr_root, fr_alpha;
    blst_fr_from_scalar(&fr_root, &s_root);
    blst_fr_cneg(&fr_alpha, &fr_root, true);  // alpha = -root

    // First handle highest degree term: q_{n-2} = a_{n-1}
    blst_scalar s_a;
    blst_scalar_from_be_bytes(&s_a, coeffs[coeff_count - 1], 32);
    blst_bendian_from_scalar(quotient[*quotient_count - 1], &s_a);

    blst_fr fr_prev;
    blst_fr_from_scalar(&fr_prev, &s_a);

    // Compute q_i downward sequentially
    for (int i = (int)coeff_count - 2; i >= 1; i--) {
        blst_scalar s_coeff;
        blst_scalar_from_be_bytes(&s_coeff, coeffs[i], 32);

        blst_fr fr_coeff, fr_prod, fr_sum;
        blst_fr_from_scalar(&fr_coeff, &s_coeff);

        // prev = coeffs[i] + prev * alpha
        blst_fr_mul(&fr_prod, &fr_prev, &fr_alpha);
        blst_fr_add(&fr_sum, &fr_coeff, &fr_prod);

        blst_scalar s_q;
        blst_scalar_from_fr(&s_q, &fr_sum);
        blst_bendian_from_scalar(quotient[i - 1], &s_q);

        fr_prev = fr_sum;  // Update prev
    }

    // Remainder r = a_0 + prev * alpha
    blst_scalar s_a0;
    blst_scalar_from_be_bytes(&s_a0, coeffs[0], 32);
    blst_fr fr_a0, fr_prod, fr_r;
    blst_fr_from_scalar(&fr_a0, &s_a0);
    blst_fr_mul(&fr_prod, &fr_prev, &fr_alpha);
    blst_fr_add(&fr_r, &fr_a0, &fr_prod);

    blst_scalar s_r;
    blst_scalar_from_fr(&s_r, &fr_r);
    blst_bendian_from_scalar(*remainder, &s_r);
}

// Polynomial multiplication: result = a * b
// Polynomial multiplication (public interface)
void poly_mul(scalar_t *result, size_t *result_count,
              const scalar_t *a, size_t a_count,
              const scalar_t *b, size_t b_count) {
    // Result polynomial degree = degree of a + degree of b
    *result_count = a_count + b_count - 1;
    
    // Initialize result to zero
    for (size_t i = 0; i < *result_count; i++) {
        memset(result[i], 0, 32);
    }
    
    // Compute convolution: result[k] = Σ_{i+j=k} a[i] * b[j]
    for (size_t i = 0; i < a_count; i++) {
        for (size_t j = 0; j < b_count; j++) {
            size_t k = i + j;
            if (k >= *result_count) continue;
            
            blst_scalar s_ai, s_bj;
            blst_scalar_from_be_bytes(&s_ai, a[i], 32);
            blst_scalar_from_be_bytes(&s_bj, b[j], 32);
            
            blst_fr fr_ai, fr_bj, fr_prod;
            blst_fr_from_scalar(&fr_ai, &s_ai);
            blst_fr_from_scalar(&fr_bj, &s_bj);
            blst_fr_mul(&fr_prod, &fr_ai, &fr_bj);
            
            blst_scalar s_prod;
            blst_scalar_from_fr(&s_prod, &fr_prod);
            
            blst_scalar s_result;
            blst_scalar_from_be_bytes(&s_result, result[k], 32);
            blst_fr fr_result, fr_sum;
            blst_fr_from_scalar(&fr_result, &s_result);
            blst_fr_add(&fr_sum, &fr_result, &fr_prod);
            
            blst_scalar s_sum;
            blst_scalar_from_fr(&s_sum, &fr_sum);
            blst_bendian_from_scalar(result[k], &s_sum);
        }
    }
}

// Compute total polynomial f_R(X) = ∏_{i=1}^t f_i(X) from all batch polynomial coefficients
static bool compute_total_poly_internal(scalar_t *f_coeffs, size_t *f_count,
                                       const system_params_t *params) {
    if (!params->batch_poly_coeffs || params->batch_count == 0) {
        // No revocations, return constant polynomial 1
        memset(f_coeffs[0], 0, 32);
        f_coeffs[0][31] = 1;
        *f_count = 1;
        return true;
    }
    
    // Start from first batch
    *f_count = params->batch_poly_counts[0];
    memcpy(f_coeffs, params->batch_poly_coeffs[0], *f_count * sizeof(scalar_t));
    
    // Multiply by subsequent batch polynomials sequentially
    // Compute maximum possible result size: sum of polynomial degrees of all batches
    size_t max_result_size = params->batch_count * params->rev_batch_size + 1;
    scalar_t *temp = (scalar_t *)malloc(max_result_size * sizeof(scalar_t));
    if (!temp) {
        return false;
    }
    
    for (size_t i = 1; i < params->batch_count; i++) {
        size_t temp_count;
        // Compute result size of this multiplication
        size_t expected_size = *f_count + params->batch_poly_counts[i] - 1;
        if (expected_size > max_result_size) {
            // Need to expand temp array
            max_result_size = expected_size;
            scalar_t *new_temp = (scalar_t *)realloc(temp, max_result_size * sizeof(scalar_t));
            if (!new_temp) {
                free(temp);
                return false;
            }
            temp = new_temp;
        }
        
        poly_mul(temp, &temp_count, f_coeffs, *f_count, 
                 params->batch_poly_coeffs[i], params->batch_poly_counts[i]);
        
        // Ensure f_coeffs has sufficient space
        if (temp_count > max_result_size) {
            free(temp);
            return false;  // This should not happen
        }
        
        memcpy(f_coeffs, temp, temp_count * sizeof(scalar_t));
        *f_count = temp_count;
    }
    
    free(temp);
    return true;
}

// Public interface: Compute total polynomial f_R(X) = ∏_{i=1}^t f_i(X) from all batch polynomial coefficients
bool compute_total_poly(scalar_t *f_coeffs, size_t *f_count,
                       const system_params_t *params) {
    return compute_total_poly_internal(f_coeffs, f_count, params);
}

// Incremental computation of total polynomial: based on cached polynomial and new batch
// cached_poly: Cached total polynomial coefficients
// cached_count: Number of cached polynomial coefficients
// cached_batch_count: Number of processed batches (unused, kept for interface consistency)
// new_batch_coeffs: New batch polynomial coefficients
// new_batch_count: Number of new batch polynomial coefficients
// result: Output result polynomial coefficients
// result_count: Number of output result polynomial coefficients
// max_result_size: Maximum capacity of result array
bool compute_total_poly_incremental(const scalar_t *cached_poly, size_t cached_count,
                                    size_t cached_batch_count,
                                    const scalar_t *new_batch_coeffs, size_t new_batch_count,
                                    scalar_t *result, size_t *result_count,
                                    size_t max_result_size) {
    (void)cached_batch_count;  // Unused, kept for interface consistency
    if (!cached_poly || cached_count == 0 || !new_batch_coeffs || new_batch_count == 0) {
        return false;
    }
    
    // Compute result size
    size_t expected_size = cached_count + new_batch_count - 1;
    if (expected_size > max_result_size) {
        return false;
    }
    
    // Multiply cached polynomial with new batch polynomial
    poly_mul(result, result_count, cached_poly, cached_count,
             new_batch_coeffs, new_batch_count);
    
    return true;
}

// Generate non-membership witness
void non_membership_witness(g1_point_t *omega, scalar_t v,
                           const system_params_t *params, const scalar_t id0) {
    // Directly use total polynomial f_R(X) stored in params (synchronized with A_t)
    if (!params->total_poly_coeffs || params->total_poly_count == 0) {
        // If no total polynomial (initial state), use constant polynomial 1
        scalar_t zero = {0};
        blst_scalar s_zero;
        blst_scalar_from_be_bytes(&s_zero, zero, 32);
        scalar_t zero_bytes;
        blst_lendian_from_scalar(zero_bytes, &s_zero);
        g1_mul(omega, &params->g1, zero_bytes);
        memset(v, 0, 32);
        v[31] = 0xff;  // -1 mod curve_order (simplified)
        return;
    }
    
    // Use stored total polynomial (no need to free, as it's part of params)
    const scalar_t *f_coeffs = params->total_poly_coeffs;
    size_t f_count = params->total_poly_count;
    
    // Special case: revocation set is empty (polynomial is constant 1)
    if (f_count == 1 && f_coeffs[0][31] == 1) {
        scalar_t zero_check = {0};
        if (memcmp(f_coeffs[0], zero_check, 31) == 0) {
            // omega = g1^0 = 1 (identity element), v = -1
            scalar_t zero = {0};
            blst_scalar s_zero;
            blst_scalar_from_be_bytes(&s_zero, zero, 32);
            scalar_t zero_bytes;
            blst_lendian_from_scalar(zero_bytes, &s_zero);
            g1_mul(omega, &params->g1, zero_bytes);
            memset(v, 0, 32);
            v[31] = 0xff;  // -1 mod curve_order (simplified)
            return;
        }
    }
    
    // v_id0 = -f_R(-id0)
    scalar_t neg_id0;
    blst_scalar s_id0;
    blst_scalar_from_be_bytes(&s_id0, id0, 32);
    
    blst_fr fr_id0, fr_neg;
    blst_fr_from_scalar(&fr_id0, &s_id0);
    blst_fr_cneg(&fr_neg, &fr_id0, true);
    
    blst_scalar s_neg;
    blst_scalar_from_fr(&s_neg, &fr_neg);
    blst_bendian_from_scalar(neg_id0, &s_neg);
    
    scalar_t f_minus;
    poly_eval(f_minus, f_coeffs, f_count, neg_id0);
    
    blst_scalar s_f_minus;
    blst_scalar_from_be_bytes(&s_f_minus, f_minus, 32);
    
    blst_fr fr_f_minus, fr_v;
    blst_fr_from_scalar(&fr_f_minus, &s_f_minus);
    blst_fr_cneg(&fr_v, &fr_f_minus, true);
    
    blst_scalar s_v;
    blst_scalar_from_fr(&s_v, &fr_v);
    blst_bendian_from_scalar(v, &s_v);
    
    // Construct h(X) = f_R(X) - f_R(-id0)
    scalar_t *h_coeffs = (scalar_t *)malloc(f_count * sizeof(scalar_t));
    if (!h_coeffs) {
        return;
    }
    memcpy(h_coeffs, f_coeffs, f_count * 32);
    
    blst_scalar s_h0, s_f_minus2;
    blst_scalar_from_be_bytes(&s_h0, h_coeffs[0], 32);
    blst_scalar_from_be_bytes(&s_f_minus2, f_minus, 32);
    
    blst_fr fr_h0, fr_f_minus2, fr_result;
    blst_fr_from_scalar(&fr_h0, &s_h0);
    blst_fr_from_scalar(&fr_f_minus2, &s_f_minus2);
    blst_fr_sub(&fr_result, &fr_h0, &fr_f_minus2);
    
    blst_scalar s_result;
    blst_scalar_from_fr(&s_result, &fr_result);
    blst_bendian_from_scalar(h_coeffs[0], &s_result);
    
    // Compute q_R(X) = h(X) / (X + id0)
    scalar_t *q_coeffs = (scalar_t *)malloc((f_count - 1) * sizeof(scalar_t));
    if (!q_coeffs) {
        free(h_coeffs);
        return;
    }
    size_t q_count;
    scalar_t rem;
    poly_div_by_linear(q_coeffs, &q_count, &rem, h_coeffs, f_count, id0);
    
    // Compute g1^{q_R(kappa)} = Σ q_i * g1^{kappa^i}
    // Initialize to identity element (g1^0)
    scalar_t zero = {0};
    blst_scalar s_zero;
    blst_scalar_from_be_bytes(&s_zero, zero, 32);
    scalar_t zero_bytes;
    blst_lendian_from_scalar(zero_bytes, &s_zero);
    g1_mul(omega, &params->g1, zero_bytes);
    
    // Check if index is within valid range
    // Note: q_count is at most R_count, and R_count should not exceed q
    // But if number of revoked IDs exceeds initial q, may need to expand capacity
    // Since params is const, we cannot expand here, so check and error
    if (q_count > params->q_capacity) {
        free(h_coeffs);
        free(q_coeffs);
        return;
    }
    
    for (size_t i = 0; i < q_count; i++) {
        if (scalar_is_zero(q_coeffs[i])) continue;
        
        // Check if index is within valid range
        if (i >= params->q_capacity || !params->g1_kappa_powers) {
            free(h_coeffs);
            free(q_coeffs);
            return;
        }
        
        g1_point_t term;
        // q_coeffs[i] is big-endian, need to convert to little-endian
        blst_scalar s_qi;
        blst_scalar_from_be_bytes(&s_qi, q_coeffs[i], 32);
        scalar_t qi_bytes;
        blst_lendian_from_scalar(qi_bytes, &s_qi);
        g1_mul(&term, &params->g1_kappa_powers[i], qi_bytes);
        
        g1_point_t new_omega;
        g1_add(&new_omega, omega, &term);
        *omega = new_omega;
    }
    
    // Free temporarily allocated memory (f_coeffs doesn't need to be freed, as it's params->total_poly_coeffs)
    free(h_coeffs);
    free(q_coeffs);
}

// Generate non-membership witness (according to GenWitness algorithm in paper)
// Returns quadruple (ω_id', A_t', g_id, π_id)
// Note: Users don't need to know kappa, can use precomputed g1^{kappa^i}
void gen_witness(non_membership_witness_t *witness,
                 const system_params_t *params, const scalar_t id0) {
    if (!witness || !params) {
        return;
    }
    
    memset(witness, 0, sizeof(non_membership_witness_t));
    
    // Get current accumulator value A_t
    g1_point_t A_t;
    if (params->accum_count > 0 && params->accum_values) {
        A_t = params->accum_values[params->accum_count - 1];
    } else {
        // Accumulator value is empty, A_t should be g1 (identity element)
        scalar_t one = {0};
        one[31] = 1;
        blst_scalar s_one;
        blst_scalar_from_be_bytes(&s_one, one, 32);
        scalar_t one_bytes;
        blst_lendian_from_scalar(one_bytes, &s_one);
        g1_mul(&A_t, &params->g1, one_bytes);
    }
    
    // Directly use total polynomial f_R(X) stored in params (synchronized with A_t)
    if (!params->total_poly_coeffs || params->total_poly_count == 0) {
        // If no total polynomial (initial state), use constant polynomial 1
        scalar_t zero = {0};
        blst_scalar s_zero;
        blst_scalar_from_be_bytes(&s_zero, zero, 32);
        scalar_t zero_bytes;
        blst_lendian_from_scalar(zero_bytes, &s_zero);
        g1_mul(&witness->omega_id_prime, &params->g1, zero_bytes);
        g1_mul(&witness->A_t_prime, &A_t, zero_bytes);
        g1_mul(&witness->g_id, &params->g1, zero_bytes);
        return;
    }
    
    // Use stored total polynomial (no need to free, as it's part of params)
    const scalar_t *f_coeffs = params->total_poly_coeffs;
    size_t f_count = params->total_poly_count;
    
    // Special case: revocation set is empty (polynomial is constant 1)
    if (f_count == 1 && f_coeffs[0][31] == 1) {
        scalar_t zero_check = {0};
        if (memcmp(f_coeffs[0], zero_check, 31) == 0) {
            // omega_id = g1^0 = 1 (identity element), g_id = g1^0 = 1
            scalar_t zero = {0};
            blst_scalar s_zero;
            blst_scalar_from_be_bytes(&s_zero, zero, 32);
            scalar_t zero_bytes;
            blst_lendian_from_scalar(zero_bytes, &s_zero);
            g1_mul(&witness->omega_id_prime, &params->g1, zero_bytes);
            g1_mul(&witness->A_t_prime, &A_t, zero_bytes);
            g1_mul(&witness->g_id, &params->g1, zero_bytes);
            return;
        }
    }
    
    // Step 1: Generate random number r_{nm}
    scalar_t r_nm;
    random_scalar(r_nm);
    
    // Step 2: Compute g_{nm} = g_1^{r_{nm}}
    blst_scalar s_r_nm;
    blst_scalar_from_be_bytes(&s_r_nm, r_nm, 32);
    scalar_t r_nm_bytes;
    blst_lendian_from_scalar(r_nm_bytes, &s_r_nm);
    g1_point_t g_nm;
    g1_mul(&g_nm, &params->g1, r_nm_bytes);
    
    // Step 3: Compute A_t' = A_t^{r_{nm}}
    g1_mul(&witness->A_t_prime, &A_t, r_nm_bytes);
    
    // Step 4: Compute v_id = -∏_{i=1}^t f_i(-id) = -f_R(-id)
    scalar_t neg_id0;
    blst_scalar s_id0;
    blst_scalar_from_be_bytes(&s_id0, id0, 32);
    
    blst_fr fr_id0, fr_neg;
    blst_fr_from_scalar(&fr_id0, &s_id0);
    blst_fr_cneg(&fr_neg, &fr_id0, true);
    
    blst_scalar s_neg;
    blst_scalar_from_fr(&s_neg, &fr_neg);
    blst_bendian_from_scalar(neg_id0, &s_neg);
    
    scalar_t f_minus_id;
    poly_eval(f_minus_id, f_coeffs, f_count, neg_id0);
    
    blst_scalar s_f_minus;
    blst_scalar_from_be_bytes(&s_f_minus, f_minus_id, 32);
    
    blst_fr fr_f_minus, fr_v_id;
    blst_fr_from_scalar(&fr_f_minus, &s_f_minus);
    blst_fr_cneg(&fr_v_id, &fr_f_minus, true);  // v_id = -f_R(-id)
    
    scalar_t v_id;
    blst_scalar s_v_id;
    blst_scalar_from_fr(&s_v_id, &fr_v_id);
    blst_bendian_from_scalar(v_id, &s_v_id);
    
    // Step 5: Compute g_id = g_{nm}^{v_id}
    blst_scalar s_v_id_for_mul;
    blst_scalar_from_be_bytes(&s_v_id_for_mul, v_id, 32);
    scalar_t v_id_bytes;
    blst_lendian_from_scalar(v_id_bytes, &s_v_id_for_mul);
    g1_mul(&witness->g_id, &g_nm, v_id_bytes);
    
    // Step 6: Compute ω_id = g_1^{(∏_{i=1}^t f_i(κ) - ∏_{i=1}^t f_i(-id))/(id + κ)}
    // This is equivalent to g_1^{(f_R(κ) - f_R(-id))/(id + κ)}
    // Use same method as non_membership_witness, compute through precomputed g1^{kappa^i}
    
    // Construct h(X) = f_R(X) - f_R(-id)
    scalar_t *h_coeffs = (scalar_t *)malloc(f_count * sizeof(scalar_t));
    if (!h_coeffs) {
        return;
    }
    memcpy(h_coeffs, f_coeffs, f_count * 32);
    
    blst_scalar s_h0, s_f_minus2;
    blst_scalar_from_be_bytes(&s_h0, h_coeffs[0], 32);
    blst_scalar_from_be_bytes(&s_f_minus2, f_minus_id, 32);
    
    blst_fr fr_h0, fr_f_minus2, fr_result;
    blst_fr_from_scalar(&fr_h0, &s_h0);
    blst_fr_from_scalar(&fr_f_minus2, &s_f_minus2);
    blst_fr_sub(&fr_result, &fr_h0, &fr_f_minus2);
    
    blst_scalar s_result;
    blst_scalar_from_fr(&s_result, &fr_result);
    blst_bendian_from_scalar(h_coeffs[0], &s_result);
    
    // Compute q_R(X) = h(X) / (X + id0)
    scalar_t *q_coeffs = (scalar_t *)malloc((f_count - 1) * sizeof(scalar_t));
    if (!q_coeffs) {
        free(h_coeffs);
        return;
    }
    size_t q_count;
    scalar_t rem;
    poly_div_by_linear(q_coeffs, &q_count, &rem, h_coeffs, f_count, id0);
    
    // Compute g1^{q_R(kappa)} = Σ q_i * g1^{kappa^i}
    // Use precomputed g1^{kappa^i}, no need to know kappa
    scalar_t zero = {0};
    blst_scalar s_zero;
    blst_scalar_from_be_bytes(&s_zero, zero, 32);
    scalar_t zero_bytes;
    blst_lendian_from_scalar(zero_bytes, &s_zero);
    g1_point_t omega_id;
    g1_mul(&omega_id, &params->g1, zero_bytes);
    
    // Check if index is within valid range
    if (q_count > params->q_capacity) {
        free(h_coeffs);
        free(q_coeffs);
        return;
    }
    
    for (size_t i = 0; i < q_count; i++) {
        if (scalar_is_zero(q_coeffs[i])) continue;
        
        if (i >= params->q_capacity || !params->g1_kappa_powers) {
            free(h_coeffs);
            free(q_coeffs);
            return;
        }
        
        g1_point_t term;
        blst_scalar s_qi;
        blst_scalar_from_be_bytes(&s_qi, q_coeffs[i], 32);
        scalar_t qi_bytes;
        blst_lendian_from_scalar(qi_bytes, &s_qi);
        g1_mul(&term, &params->g1_kappa_powers[i], qi_bytes);
        
        g1_point_t new_omega;
        g1_add(&new_omega, &omega_id, &term);
        omega_id = new_omega;
    }
    
    // Step 7: Compute ω_id' = ω_id^{r_{nm}}
    g1_mul(&witness->omega_id_prime, &omega_id, r_nm_bytes);
    
    // Step 8: Generate proof π_id: prove relation (v_id, r_{nm})
    // π_id proves: g_{nm} = g_1^{r_{nm}} ∧ g_id = g_{nm}^{v_id} ∧ A_t' = A_t^{r_{nm}}
    // Use batch Schnorr proof
    size_t batch_count = 3;
    g1_point_t *batch_bases = (g1_point_t *)malloc(batch_count * sizeof(g1_point_t));
    g1_point_t *batch_ys = (g1_point_t *)malloc(batch_count * sizeof(g1_point_t));
    scalar_t *batch_ws = (scalar_t *)malloc(batch_count * sizeof(scalar_t));
    
    if (!batch_bases || !batch_ys || !batch_ws) {
        free(h_coeffs);
        free(q_coeffs);
        if (batch_bases) free(batch_bases);
        if (batch_ys) free(batch_ys);
        if (batch_ws) free(batch_ws);
        return;
    }
    
    // First: g_{nm} = g_1^{r_{nm}}
    batch_bases[0] = params->g1;
    batch_ys[0] = g_nm;
    memcpy(batch_ws[0], r_nm, 32);
    
    // Second: g_id = g_{nm}^{v_id}
    batch_bases[1] = g_nm;
    batch_ys[1] = witness->g_id;
    memcpy(batch_ws[1], v_id, 32);
    
    // Third: A_t' = A_t^{r_{nm}}
    batch_bases[2] = A_t;
    batch_ys[2] = witness->A_t_prime;
    memcpy(batch_ws[2], r_nm, 32);
    
    schnorr_proof_t *batch_proofs = (schnorr_proof_t *)malloc(batch_count * sizeof(schnorr_proof_t));
    if (!batch_proofs) {
        free(h_coeffs);
        free(q_coeffs);
        free(batch_bases);
        free(batch_ys);
        free(batch_ws);
        return;
    }
    
    byte tag_pi_id[] = "pi_id_vid_rnm";
    scalar_t c_pi_id;
    schnorr_batch_prove(batch_proofs, batch_bases, batch_ys, batch_ws, batch_count,
                        tag_pi_id, sizeof(tag_pi_id) - 1, r_nm, c_pi_id);
    
    // Store batch proof result to witness->pi_id (use first proof as representative)
    witness->pi_id = batch_proofs[0];
    
    free(batch_proofs);
    free(batch_bases);
    free(batch_ys);
    free(batch_ws);
    free(h_coeffs);
    free(q_coeffs);
    
    // Free temporarily allocated memory (f_coeffs doesn't need to be freed, as it's params->total_poly_coeffs)
}

// Generate non-membership witness (with timing version)
// timing: If not NULL, will record timing for each part
// use_optimized: Deprecated, kept for interface compatibility (now always uses params->total_poly_coeffs)
void gen_witness_with_timing(non_membership_witness_t *witness,
                            const system_params_t *params, const scalar_t id0,
                            gen_witness_timing_t *timing, bool use_optimized) {
    (void)use_optimized;  // Unused parameter, avoid warning
    if (!witness || !params) {
        return;
    }
    
    // Initialize timing structure
    if (timing) {
        memset(timing, 0, sizeof(gen_witness_timing_t));
    }
    
    memset(witness, 0, sizeof(non_membership_witness_t));
    
    // Get current accumulator value A_t
    g1_point_t A_t;
    if (params->accum_count > 0 && params->accum_values) {
        A_t = params->accum_values[params->accum_count - 1];
    } else {
        // Accumulator value is empty, A_t should be g1 (identity element)
        scalar_t one = {0};
        one[31] = 1;
        blst_scalar s_one;
        blst_scalar_from_be_bytes(&s_one, one, 32);
        scalar_t one_bytes;
        blst_lendian_from_scalar(one_bytes, &s_one);
        g1_mul(&A_t, &params->g1, one_bytes);
    }
    
    // Directly use total polynomial f_R(X) stored in params (synchronized with A_t)
    if (!params->total_poly_coeffs || params->total_poly_count == 0) {
        // If no total polynomial (initial state), use constant polynomial 1
        scalar_t zero = {0};
        blst_scalar s_zero;
        blst_scalar_from_be_bytes(&s_zero, zero, 32);
        scalar_t zero_bytes;
        blst_lendian_from_scalar(zero_bytes, &s_zero);
        g1_mul(&witness->omega_id_prime, &params->g1, zero_bytes);
        g1_mul(&witness->A_t_prime, &A_t, zero_bytes);
        g1_mul(&witness->g_id, &params->g1, zero_bytes);
        if (timing) {
            timing->compute_total_poly_time = 0.0;  // Already computed in revoke_id
        }
        return;
    }
    
    // Use stored total polynomial (no need to free, as it's part of params)
    // Timing set to 0, because already computed in revoke_id
    if (timing) {
        timing->compute_total_poly_time = 0.0;
    }
    
    const scalar_t *f_coeffs = params->total_poly_coeffs;
    size_t f_count = params->total_poly_count;
    
    // Special case: revocation set is empty (polynomial is constant 1)
    if (f_count == 1 && f_coeffs[0][31] == 1) {
        scalar_t zero_check = {0};
        if (memcmp(f_coeffs[0], zero_check, 31) == 0) {
            // omega_id = g1^0 = 1 (identity element), g_id = g1^0 = 1
            scalar_t zero = {0};
            blst_scalar s_zero;
            blst_scalar_from_be_bytes(&s_zero, zero, 32);
            scalar_t zero_bytes;
            blst_lendian_from_scalar(zero_bytes, &s_zero);
            g1_mul(&witness->omega_id_prime, &params->g1, zero_bytes);
            g1_mul(&witness->A_t_prime, &A_t, zero_bytes);
            g1_mul(&witness->g_id, &params->g1, zero_bytes);
            return;
        }
    }
    
    // Step 1: Generate random number r_{nm}
    scalar_t r_nm;
    random_scalar(r_nm);
    
    // Step 2: Compute g_{nm} = g_1^{r_{nm}}
    blst_scalar s_r_nm;
    blst_scalar_from_be_bytes(&s_r_nm, r_nm, 32);
    scalar_t r_nm_bytes;
    blst_lendian_from_scalar(r_nm_bytes, &s_r_nm);
    g1_point_t g_nm;
    g1_mul(&g_nm, &params->g1, r_nm_bytes);
    
    // Step 3: Compute A_t' = A_t^{r_{nm}}
    g1_mul(&witness->A_t_prime, &A_t, r_nm_bytes);
    
    // Step 4: Compute v_id = -∏_{i=1}^t f_i(-id) = -f_R(-id)
    scalar_t neg_id0;
    blst_scalar s_id0;
    blst_scalar_from_be_bytes(&s_id0, id0, 32);
    
    blst_fr fr_id0, fr_neg;
    blst_fr_from_scalar(&fr_id0, &s_id0);
    blst_fr_cneg(&fr_neg, &fr_id0, true);
    
    blst_scalar s_neg;
    blst_scalar_from_fr(&s_neg, &fr_neg);
    blst_bendian_from_scalar(neg_id0, &s_neg);
    
    scalar_t f_minus_id;
    double start_poly_eval = get_time_us();
    poly_eval(f_minus_id, f_coeffs, f_count, neg_id0);
    if (timing) {
        timing->poly_eval_time = get_time_us() - start_poly_eval;
    }
    
    blst_scalar s_f_minus;
    blst_scalar_from_be_bytes(&s_f_minus, f_minus_id, 32);
    
    blst_fr fr_f_minus, fr_v_id;
    blst_fr_from_scalar(&fr_f_minus, &s_f_minus);
    blst_fr_cneg(&fr_v_id, &fr_f_minus, true);  // v_id = -f_R(-id)
    
    scalar_t v_id;
    blst_scalar s_v_id;
    blst_scalar_from_fr(&s_v_id, &fr_v_id);
    blst_bendian_from_scalar(v_id, &s_v_id);
    
    // Step 5: Compute g_id = g_{nm}^{v_id}
    blst_scalar s_v_id_for_mul;
    blst_scalar_from_be_bytes(&s_v_id_for_mul, v_id, 32);
    scalar_t v_id_bytes;
    blst_lendian_from_scalar(v_id_bytes, &s_v_id_for_mul);
    g1_mul(&witness->g_id, &g_nm, v_id_bytes);
    
    // Step 6: Compute ω_id = g_1^{(∏_{i=1}^t f_i(κ) - ∏_{i=1}^t f_i(-id))/(id + κ)}
    // This is equivalent to g_1^{(f_R(κ) - f_R(-id))/(id + κ)}
    // Use same method as non_membership_witness, compute through precomputed g1^{kappa^i}
    
    // Construct h(X) = f_R(X) - f_R(-id)
    scalar_t *h_coeffs = (scalar_t *)malloc(f_count * sizeof(scalar_t));
    if (!h_coeffs) {
        return;
    }
    memcpy(h_coeffs, f_coeffs, f_count * 32);
    
    blst_scalar s_h0, s_f_minus2;
    blst_scalar_from_be_bytes(&s_h0, h_coeffs[0], 32);
    blst_scalar_from_be_bytes(&s_f_minus2, f_minus_id, 32);
    
    blst_fr fr_h0, fr_f_minus2, fr_result;
    blst_fr_from_scalar(&fr_h0, &s_h0);
    blst_fr_from_scalar(&fr_f_minus2, &s_f_minus2);
    blst_fr_sub(&fr_result, &fr_h0, &fr_f_minus2);
    
    blst_scalar s_result;
    blst_scalar_from_fr(&s_result, &fr_result);
    blst_bendian_from_scalar(h_coeffs[0], &s_result);
    
    // Compute q_R(X) = h(X) / (X + id0)
    scalar_t *q_coeffs = (scalar_t *)malloc((f_count - 1) * sizeof(scalar_t));
    if (!q_coeffs) {
        free(h_coeffs);
        return;
    }
    size_t q_count;
    scalar_t rem;
    double start_poly_div = get_time_us();
    poly_div_by_linear(q_coeffs, &q_count, &rem, h_coeffs, f_count, id0);
    if (timing) {
        timing->poly_div_time = get_time_us() - start_poly_div;
    }
    
    // Compute g1^{q_R(kappa)} = Σ q_i * g1^{kappa^i}
    // Use precomputed g1^{kappa^i}, no need to know kappa
    scalar_t zero = {0};
    blst_scalar s_zero;
    blst_scalar_from_be_bytes(&s_zero, zero, 32);
    scalar_t zero_bytes;
    blst_lendian_from_scalar(zero_bytes, &s_zero);
    g1_point_t omega_id;
    g1_mul(&omega_id, &params->g1, zero_bytes);
    
    // Check if index is within valid range
    if (q_count > params->q_capacity) {
        free(h_coeffs);
        free(q_coeffs);
        return;
    }
    
    double start_omega_loop = get_time_us();
    for (size_t i = 0; i < q_count; i++) {
        if (scalar_is_zero(q_coeffs[i])) continue;
        
        if (i >= params->q_capacity || !params->g1_kappa_powers) {
            free(h_coeffs);
            free(q_coeffs);
            return;
        }
        
        g1_point_t term;
        blst_scalar s_qi;
        blst_scalar_from_be_bytes(&s_qi, q_coeffs[i], 32);
        scalar_t qi_bytes;
        blst_lendian_from_scalar(qi_bytes, &s_qi);
        g1_mul(&term, &params->g1_kappa_powers[i], qi_bytes);
        
        g1_point_t new_omega;
        g1_add(&new_omega, &omega_id, &term);
        omega_id = new_omega;
    }
    if (timing) {
        timing->omega_loop_time = get_time_us() - start_omega_loop;
    }
    
    // Step 7: Compute ω_id' = ω_id^{r_{nm}}
    g1_mul(&witness->omega_id_prime, &omega_id, r_nm_bytes);
    
    // Step 8: Generate proof π_id: prove relation (v_id, r_{nm})
    // π_id proves: g_{nm} = g_1^{r_{nm}} ∧ g_id = g_{nm}^{v_id} ∧ A_t' = A_t^{r_{nm}}
    // Use batch Schnorr proof
    size_t batch_count = 3;
    g1_point_t *batch_bases = (g1_point_t *)malloc(batch_count * sizeof(g1_point_t));
    g1_point_t *batch_ys = (g1_point_t *)malloc(batch_count * sizeof(g1_point_t));
    scalar_t *batch_ws = (scalar_t *)malloc(batch_count * sizeof(scalar_t));
    
    if (!batch_bases || !batch_ys || !batch_ws) {
        free(h_coeffs);
        free(q_coeffs);
        if (batch_bases) free(batch_bases);
        if (batch_ys) free(batch_ys);
        if (batch_ws) free(batch_ws);
        return;
    }
    
    // First: g_{nm} = g_1^{r_{nm}}
    batch_bases[0] = params->g1;
    batch_ys[0] = g_nm;
    memcpy(batch_ws[0], r_nm, 32);
    
    // Second: g_id = g_{nm}^{v_id}
    batch_bases[1] = g_nm;
    batch_ys[1] = witness->g_id;
    memcpy(batch_ws[1], v_id, 32);
    
    // Third: A_t' = A_t^{r_{nm}}
    batch_bases[2] = A_t;
    batch_ys[2] = witness->A_t_prime;
    memcpy(batch_ws[2], r_nm, 32);
    
    schnorr_proof_t *batch_proofs = (schnorr_proof_t *)malloc(batch_count * sizeof(schnorr_proof_t));
    if (!batch_proofs) {
        free(h_coeffs);
        free(q_coeffs);
        free(batch_bases);
        free(batch_ys);
        free(batch_ws);
        return;
    }
    
    byte tag_pi_id[] = "pi_id_vid_rnm";
    scalar_t c_pi_id;
    double start_pi_id = get_time_us();
    schnorr_batch_prove(batch_proofs, batch_bases, batch_ys, batch_ws, batch_count,
                        tag_pi_id, sizeof(tag_pi_id) - 1, r_nm, c_pi_id);
    if (timing) {
        timing->gid_piid_time = get_time_us() - start_pi_id;
    }
    
    // Store batch proof result to witness->pi_id (use first proof as representative)
    witness->pi_id = batch_proofs[0];
    
    free(batch_proofs);
    free(batch_bases);
    free(batch_ys);
    free(batch_ws);
    free(h_coeffs);
    free(q_coeffs);
    
    // Free temporarily allocated memory (f_coeffs doesn't need to be freed, as it's params->total_poly_coeffs)
}

// Thread parameter structure for multithreaded omega_id computation
typedef struct {
    const system_params_t *params;
    const scalar_t *q_coeffs;
    size_t q_count;
    size_t start_idx;
    size_t end_idx;
    g1_point_t partial_sum;  // Partial sum
} omega_thread_arg_t;

// Thread worker function: compute partial omega_id
static void *compute_omega_partial(void *arg) {
    omega_thread_arg_t *thread_arg = (omega_thread_arg_t *)arg;
    const system_params_t *params = thread_arg->params;
    const scalar_t *q_coeffs = thread_arg->q_coeffs;
    
    // Initialize partial sum to 0
    scalar_t zero = {0};
    blst_scalar s_zero;
    blst_scalar_from_be_bytes(&s_zero, zero, 32);
    scalar_t zero_bytes;
    blst_lendian_from_scalar(zero_bytes, &s_zero);
    g1_mul(&thread_arg->partial_sum, &params->g1, zero_bytes);
    
    // Compute terms in specified range
    for (size_t i = thread_arg->start_idx; i < thread_arg->end_idx; i++) {
        if (scalar_is_zero(q_coeffs[i])) continue;
        
        if (i >= params->q_capacity || !params->g1_kappa_powers) {
            return NULL;
        }
        
        g1_point_t term;
        blst_scalar s_qi;
        blst_scalar_from_be_bytes(&s_qi, q_coeffs[i], 32);
        scalar_t qi_bytes;
        blst_lendian_from_scalar(qi_bytes, &s_qi);
        g1_mul(&term, &params->g1_kappa_powers[i], qi_bytes);
        
        g1_point_t new_sum;
        g1_add(&new_sum, &thread_arg->partial_sum, &term);
        thread_arg->partial_sum = new_sum;
    }
    
    return NULL;
}

// Generate non-membership witness (multithreaded version)
// Use multithreading to parallel compute omega_id, improve performance
// num_threads: Number of threads, if 0 then automatically detect CPU core count
void gen_witness_multithread(non_membership_witness_t *witness,
                            const system_params_t *params, const scalar_t id0,
                            size_t num_threads) {
    if (!witness || !params) {
        return;
    }
    
    memset(witness, 0, sizeof(non_membership_witness_t));
    
    // Get current accumulator value A_t
    g1_point_t A_t;
    if (params->accum_count > 0 && params->accum_values) {
        A_t = params->accum_values[params->accum_count - 1];
    } else {
        // Accumulator value is empty, A_t should be g1 (identity element)
        scalar_t one = {0};
        one[31] = 1;
        blst_scalar s_one;
        blst_scalar_from_be_bytes(&s_one, one, 32);
        scalar_t one_bytes;
        blst_lendian_from_scalar(one_bytes, &s_one);
        g1_mul(&A_t, &params->g1, one_bytes);
    }
    
    // Directly use total polynomial f_R(X) stored in params (synchronized with A_t)
    if (!params->total_poly_coeffs || params->total_poly_count == 0) {
        // If no total polynomial (initial state), use constant polynomial 1
        scalar_t zero = {0};
        blst_scalar s_zero;
        blst_scalar_from_be_bytes(&s_zero, zero, 32);
        scalar_t zero_bytes;
        blst_lendian_from_scalar(zero_bytes, &s_zero);
        g1_mul(&witness->omega_id_prime, &params->g1, zero_bytes);
        g1_mul(&witness->A_t_prime, &A_t, zero_bytes);
        g1_mul(&witness->g_id, &params->g1, zero_bytes);
        return;
    }
    
    // Use stored total polynomial (no need to free, as it's part of params)
    const scalar_t *f_coeffs = params->total_poly_coeffs;
    size_t f_count = params->total_poly_count;
    
    // Special case: revocation set is empty (polynomial is constant 1)
    if (f_count == 1 && f_coeffs[0][31] == 1) {
        scalar_t zero_check = {0};
        if (memcmp(f_coeffs[0], zero_check, 31) == 0) {
            // omega_id = g1^0 = 1 (identity element), g_id = g1^0 = 1
            scalar_t zero = {0};
            blst_scalar s_zero;
            blst_scalar_from_be_bytes(&s_zero, zero, 32);
            scalar_t zero_bytes;
            blst_lendian_from_scalar(zero_bytes, &s_zero);
            g1_mul(&witness->omega_id_prime, &params->g1, zero_bytes);
            g1_mul(&witness->A_t_prime, &A_t, zero_bytes);
            g1_mul(&witness->g_id, &params->g1, zero_bytes);
            return;
        }
    }
    
    // Step 1: Generate random number r_{nm}
    scalar_t r_nm;
    random_scalar(r_nm);
    
    // Step 2: Compute g_{nm} = g_1^{r_{nm}}
    blst_scalar s_r_nm;
    blst_scalar_from_be_bytes(&s_r_nm, r_nm, 32);
    scalar_t r_nm_bytes;
    blst_lendian_from_scalar(r_nm_bytes, &s_r_nm);
    g1_point_t g_nm;
    g1_mul(&g_nm, &params->g1, r_nm_bytes);
    
    // Step 3: Compute A_t' = A_t^{r_{nm}}
    g1_mul(&witness->A_t_prime, &A_t, r_nm_bytes);
    
    // Step 4: Compute v_id = -∏_{i=1}^t f_i(-id) = -f_R(-id)
    scalar_t neg_id0;
    blst_scalar s_id0;
    blst_scalar_from_be_bytes(&s_id0, id0, 32);
    
    blst_fr fr_id0, fr_neg;
    blst_fr_from_scalar(&fr_id0, &s_id0);
    blst_fr_cneg(&fr_neg, &fr_id0, true);
    
    blst_scalar s_neg;
    blst_scalar_from_fr(&s_neg, &fr_neg);
    blst_bendian_from_scalar(neg_id0, &s_neg);
    
    scalar_t f_minus_id;
    poly_eval(f_minus_id, f_coeffs, f_count, neg_id0);
    
    blst_scalar s_f_minus;
    blst_scalar_from_be_bytes(&s_f_minus, f_minus_id, 32);
    
    blst_fr fr_f_minus, fr_v_id;
    blst_fr_from_scalar(&fr_f_minus, &s_f_minus);
    blst_fr_cneg(&fr_v_id, &fr_f_minus, true);  // v_id = -f_R(-id)
    
    scalar_t v_id;
    blst_scalar s_v_id;
    blst_scalar_from_fr(&s_v_id, &fr_v_id);
    blst_bendian_from_scalar(v_id, &s_v_id);
    
    // Step 5: Compute g_id = g_{nm}^{v_id}
    blst_scalar s_v_id_for_mul;
    blst_scalar_from_be_bytes(&s_v_id_for_mul, v_id, 32);
    scalar_t v_id_bytes;
    blst_lendian_from_scalar(v_id_bytes, &s_v_id_for_mul);
    g1_mul(&witness->g_id, &g_nm, v_id_bytes);
    
    // Step 6: Compute ω_id = g_1^{(∏_{i=1}^t f_i(κ) - ∏_{i=1}^t f_i(-id))/(id + κ)}
    // This is equivalent to g_1^{(f_R(κ) - f_R(-id))/(id + κ)}
    // Use same method as non_membership_witness, compute through precomputed g1^{kappa^i}
    
    // Construct h(X) = f_R(X) - f_R(-id)
    scalar_t *h_coeffs = (scalar_t *)malloc(f_count * sizeof(scalar_t));
    if (!h_coeffs) {
        return;
    }
    memcpy(h_coeffs, f_coeffs, f_count * 32);
    
    blst_scalar s_h0, s_f_minus2;
    blst_scalar_from_be_bytes(&s_h0, h_coeffs[0], 32);
    blst_scalar_from_be_bytes(&s_f_minus2, f_minus_id, 32);
    
    blst_fr fr_h0, fr_f_minus2, fr_result;
    blst_fr_from_scalar(&fr_h0, &s_h0);
    blst_fr_from_scalar(&fr_f_minus2, &s_f_minus2);
    blst_fr_sub(&fr_result, &fr_h0, &fr_f_minus2);
    
    blst_scalar s_result;
    blst_scalar_from_fr(&s_result, &fr_result);
    blst_bendian_from_scalar(h_coeffs[0], &s_result);
    
    // Compute q_R(X) = h(X) / (X + id0)
    scalar_t *q_coeffs = (scalar_t *)malloc((f_count - 1) * sizeof(scalar_t));
    if (!q_coeffs) {
        free(h_coeffs);
        return;
    }
    size_t q_count;
    scalar_t rem;
    poly_div_by_linear(q_coeffs, &q_count, &rem, h_coeffs, f_count, id0);
    
    // Compute g1^{q_R(kappa)} = Σ q_i * g1^{kappa^i}
    // Use precomputed g1^{kappa^i}, no need to know kappa
    scalar_t zero = {0};
    blst_scalar s_zero;
    blst_scalar_from_be_bytes(&s_zero, zero, 32);
    scalar_t zero_bytes;
    blst_lendian_from_scalar(zero_bytes, &s_zero);
    g1_point_t omega_id;
    g1_mul(&omega_id, &params->g1, zero_bytes);
    
    // Check if index is within valid range
    if (q_count > params->q_capacity) {
        free(h_coeffs);
        free(q_coeffs);
        return;
    }
    
    // Multithreaded parallel computation of omega_id
    // If num_threads is 0, automatically detect CPU core count
    if (num_threads == 0) {
        num_threads = (size_t)sysconf(_SC_NPROCESSORS_ONLN);
        if (num_threads == 0) {
            num_threads = 1;  // If detection fails, use single thread
        }
    }
    
    // Limit maximum thread count to avoid context switching overhead from too many threads
    // Usually no more than 2x CPU core count, and no more than 64
    size_t max_threads = (size_t)sysconf(_SC_NPROCESSORS_ONLN);
    if (max_threads == 0) max_threads = 8;  // Default 8
    if (max_threads > 64) max_threads = 64;  // Maximum 64
    if (num_threads > max_threads * 2) {
        num_threads = max_threads * 2;
    }
    
    // If q_count is too small, single-threaded version is more efficient
    // Each thread needs to process at least a certain number of items to offset thread overhead
    const size_t min_items_per_thread = 10;  // Each thread processes at least 10 items
    if (q_count < num_threads * min_items_per_thread) {
        // Fall back to single-threaded version
        for (size_t i = 0; i < q_count; i++) {
            if (scalar_is_zero(q_coeffs[i])) continue;
            
            if (i >= params->q_capacity || !params->g1_kappa_powers) {
                free(h_coeffs);
                free(q_coeffs);
                return;
            }
            
            g1_point_t term;
            blst_scalar s_qi;
            blst_scalar_from_be_bytes(&s_qi, q_coeffs[i], 32);
            scalar_t qi_bytes;
            blst_lendian_from_scalar(qi_bytes, &s_qi);
            g1_mul(&term, &params->g1_kappa_powers[i], qi_bytes);
            
            g1_point_t new_omega;
            g1_add(&new_omega, &omega_id, &term);
            omega_id = new_omega;
        }
    } else {
        // Multithreaded version
        pthread_t *threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
        omega_thread_arg_t *thread_args = (omega_thread_arg_t *)malloc(num_threads * sizeof(omega_thread_arg_t));
        
        if (!threads || !thread_args) {
            // Memory allocation failed, fall back to single-threaded
            free(threads);
            free(thread_args);
            for (size_t i = 0; i < q_count; i++) {
                if (scalar_is_zero(q_coeffs[i])) continue;
                
                if (i >= params->q_capacity || !params->g1_kappa_powers) {
                    free(h_coeffs);
                    free(q_coeffs);
                    return;
                }
                
                g1_point_t term;
                blst_scalar s_qi;
                blst_scalar_from_be_bytes(&s_qi, q_coeffs[i], 32);
                scalar_t qi_bytes;
                blst_lendian_from_scalar(qi_bytes, &s_qi);
                g1_mul(&term, &params->g1_kappa_powers[i], qi_bytes);
                
                g1_point_t new_omega;
                g1_add(&new_omega, &omega_id, &term);
                omega_id = new_omega;
            }
        } else {
            // Distribute work to each thread
            size_t items_per_thread = q_count / num_threads;
            size_t remainder = q_count % num_threads;
            
            size_t start_idx = 0;
            for (size_t t = 0; t < num_threads; t++) {
                thread_args[t].params = params;
                thread_args[t].q_coeffs = q_coeffs;
                thread_args[t].q_count = q_count;
                thread_args[t].start_idx = start_idx;
                
                // Distribute work, remainder assigned to earlier threads
                size_t thread_items = items_per_thread + (t < remainder ? 1 : 0);
                thread_args[t].end_idx = start_idx + thread_items;
                
                start_idx = thread_args[t].end_idx;
                
                // Create thread
                if (pthread_create(&threads[t], NULL, compute_omega_partial, &thread_args[t]) != 0) {
                    // Thread creation failed, cleanup and fall back to single-threaded
                    for (size_t j = 0; j < t; j++) {
                        pthread_join(threads[j], NULL);
                    }
                    free(threads);
                    free(thread_args);
                    // Fall back to single-threaded version
                    for (size_t i = 0; i < q_count; i++) {
                        if (scalar_is_zero(q_coeffs[i])) continue;
                        
                        if (i >= params->q_capacity || !params->g1_kappa_powers) {
                            free(h_coeffs);
                            free(q_coeffs);
                            return;
                        }
                        
                        g1_point_t term;
                        blst_scalar s_qi;
                        blst_scalar_from_be_bytes(&s_qi, q_coeffs[i], 32);
                        scalar_t qi_bytes;
                        blst_lendian_from_scalar(qi_bytes, &s_qi);
                        g1_mul(&term, &params->g1_kappa_powers[i], qi_bytes);
                        
                        g1_point_t new_omega;
                        g1_add(&new_omega, &omega_id, &term);
                        omega_id = new_omega;
                    }
                    free(h_coeffs);
                    free(q_coeffs);
                    return;
                }
            }
            
            // Wait for all threads to complete
            for (size_t t = 0; t < num_threads; t++) {
                pthread_join(threads[t], NULL);
            }
            
            // Merge partial sums from all threads
            for (size_t t = 0; t < num_threads; t++) {
                g1_point_t new_omega;
                g1_add(&new_omega, &omega_id, &thread_args[t].partial_sum);
                omega_id = new_omega;
            }
            
            free(threads);
            free(thread_args);
        }
    }
    
    // Step 7: Compute ω_id' = ω_id^{r_{nm}}
    g1_mul(&witness->omega_id_prime, &omega_id, r_nm_bytes);
    
    // Step 8: Generate proof π_id: prove relation (v_id, r_{nm})
    // π_id proves: g_{nm} = g_1^{r_{nm}} ∧ g_id = g_{nm}^{v_id} ∧ A_t' = A_t^{r_{nm}}
    // Use batch Schnorr proof
    size_t batch_count = 3;
    g1_point_t *batch_bases = (g1_point_t *)malloc(batch_count * sizeof(g1_point_t));
    g1_point_t *batch_ys = (g1_point_t *)malloc(batch_count * sizeof(g1_point_t));
    scalar_t *batch_ws = (scalar_t *)malloc(batch_count * sizeof(scalar_t));
    
    if (!batch_bases || !batch_ys || !batch_ws) {
        free(h_coeffs);
        free(q_coeffs);
        if (batch_bases) free(batch_bases);
        if (batch_ys) free(batch_ys);
        if (batch_ws) free(batch_ws);
        return;
    }
    
    // First: g_{nm} = g_1^{r_{nm}}
    batch_bases[0] = params->g1;
    batch_ys[0] = g_nm;
    memcpy(batch_ws[0], r_nm, 32);
    
    // Second: g_id = g_{nm}^{v_id}
    batch_bases[1] = g_nm;
    batch_ys[1] = witness->g_id;
    memcpy(batch_ws[1], v_id, 32);
    
    // Third: A_t' = A_t^{r_{nm}}
    batch_bases[2] = A_t;
    batch_ys[2] = witness->A_t_prime;
    memcpy(batch_ws[2], r_nm, 32);
    
    schnorr_proof_t *batch_proofs = (schnorr_proof_t *)malloc(batch_count * sizeof(schnorr_proof_t));
    if (!batch_proofs) {
        free(h_coeffs);
        free(q_coeffs);
        free(batch_bases);
        free(batch_ys);
        free(batch_ws);
        return;
    }
    
    byte tag_pi_id[] = "pi_id_vid_rnm";
    scalar_t c_pi_id;
    schnorr_batch_prove(batch_proofs, batch_bases, batch_ys, batch_ws, batch_count,
                        tag_pi_id, sizeof(tag_pi_id) - 1, r_nm, c_pi_id);
    
    // Store batch proof result to witness->pi_id (use first proof as representative)
    witness->pi_id = batch_proofs[0];
    
    free(batch_proofs);
    free(batch_bases);
    free(batch_ys);
    free(batch_ws);
    free(h_coeffs);
    free(q_coeffs);
    
    // Free temporarily allocated memory (f_coeffs doesn't need to be freed, as it's params->total_poly_coeffs)
}

