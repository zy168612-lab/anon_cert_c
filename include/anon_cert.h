/*
 * anon_cert - Anonymous certificate system C implementation
 * Uses blst library for BLS12-381 elliptic curve operations
 */

#ifndef ANON_CERT_H
#define ANON_CERT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "blst.h"

// Scalar type (256 bits)
typedef byte scalar_t[32];

// G1 point type (blst format)
typedef blst_p1 g1_point_t;

// G2 point type (blst format)
typedef blst_p2 g2_point_t;

// G1 affine point type
typedef blst_p1_affine g1_affine_t;

// G2 affine point type
typedef blst_p2_affine g2_affine_t;

// Pairing result type
typedef blst_fp12 pairing_result_t;

// Maximum number of attributes
#define MAX_ATTRS 128

// System parameters structure
typedef struct {
    scalar_t p;  // Curve order
    g1_point_t g1;  // G1 generator
    g2_point_t g2;  // G2 generator
    g1_point_t hs[MAX_ATTRS + 1];  // Attribute bases h_0 .. h_l
    size_t max_attrs;  // Maximum number of attributes
    g2_point_t X2;  // Issuer public key
    
    // Accumulator related
    g2_point_t g2_kappa;  // g2^{kappa}
    g1_point_t *g1_kappa_powers;  // g1^{kappa^i}, dynamically allocated
    size_t q;  // Accumulator capacity (can grow dynamically)
    size_t q_capacity;  // Currently allocated capacity
    
    // Revocation state (dynamically allocated)
    // Note: No longer storing revoked_ids, instead storing polynomial coefficients per batch
    scalar_t **batch_poly_coeffs;  // Polynomial coefficient arrays per batch (dynamically allocated)
    size_t *batch_poly_counts;    // Number of polynomial coefficients per batch
    size_t batch_count;           // Number of batches
    size_t batch_capacity;        // Currently allocated batch capacity
    g1_point_t *accum_values;
    size_t accum_count;
    size_t accum_capacity;  // Currently allocated capacity
    // Fixed batch revocation parameters
    size_t rev_batch_size;        // Fixed batch size n_group (public parameter)
    // Total polynomial f_R(X) = ∏_{i=1}^t f_i(X) (public parameter, synchronized with A_t)
    scalar_t *total_poly_coeffs;  // Total polynomial coefficient array (dynamically allocated)
    size_t total_poly_count;       // Number of total polynomial coefficients
    size_t total_poly_capacity;    // Currently allocated capacity
} system_params_t;

// Issuer-side secret keys (should not appear in public parameters)
typedef struct {
    scalar_t x;      // Issuer signing private key
    scalar_t kappa;  // Accumulator secret
    // Temporary state for fixed batch revocation (confidential)
    scalar_t *pending_revokes;    // Pending revocation IDs not yet in a full batch (confidential)
    size_t pending_count;         // Number of IDs collected in current batch
    // ID allocation (dynamically allocated, confidential)
    scalar_t *issued_ids;  // Stored IDs are scalars in mod r space (confidential)
    size_t issued_count;
    size_t issued_capacity;  // Currently allocated capacity
} issuer_keys_t;

// Certificate structure
typedef struct {
    g1_point_t A;  // Signature point
    scalar_t e;  // Signature scalar
    scalar_t m[MAX_ATTRS + 1];  // Attribute vector [m0=id, m1..ml]
    size_t attr_count;  // Number of attributes (including id)
} certificate_t;

// Schnorr proof structure
typedef struct {
    g1_point_t R;  // Commitment
    scalar_t s;  // Response
} schnorr_proof_t;

// Non-membership witness structure (according to GenWitness algorithm in paper)
typedef struct {
    g1_point_t omega_id_prime;  // ω_id' = ω_id^{r_{nm}}, where ω_id = g_1^{(∏_{i=1}^t f_i(κ) - ∏_{i=1}^t f_i(-id))/(id + κ)}
    g1_point_t A_t_prime;       // A_t' = A_t^{r_{nm}}
    g1_point_t g_id;            // g_id = g_{nm}^{v_id}, where g_{nm} = g_1^{r_{nm}}, v_id = -∏_{i=1}^t f_i(-id)
    schnorr_proof_t pi_id;       // π_id: proof of relation (v_id, r_{nm})
} non_membership_witness_t;

// Full attribute disclosure verification view
typedef struct {
    g1_point_t overA;
    g1_point_t overB;
    g1_point_t U;
    scalar_t c;
    scalar_t s;
    scalar_t t;
    scalar_t cert_m[MAX_ATTRS + 1];
    size_t cert_m_len;
} full_show_view_t;

// Selective disclosure verification view
typedef struct {
    int J[MAX_ATTRS];  // Public attribute indices
    size_t J_count;
    int I_prime[MAX_ATTRS + 1];  // Hidden attribute indices
    size_t I_prime_count;
    g1_point_t C_J;
    g1_point_t C_J_prime;
    g1_point_t overA;
    g1_point_t overA_prime;
    g1_point_t overB;
    g1_point_t U;
    g1_point_t h_prime[MAX_ATTRS + 1];
    g1_point_t h_dblprime[MAX_ATTRS + 1];
    schnorr_proof_t pi1_CJ;
    schnorr_proof_t pi1_hr[MAX_ATTRS + 1];
    schnorr_proof_t pi1_hm[MAX_ATTRS + 1];
    size_t pi1_hr_count;
    size_t pi1_hm_count;
    schnorr_proof_t pi2;
    g2_point_t g_r;
    g2_point_t g2_p;
    g2_point_t g2_pp;
    non_membership_witness_t witness;  // Non-membership witness (ω_id', A_t', g_id, π_id)
    scalar_t c;
    scalar_t s;
    scalar_t t1;
    scalar_t u_dict[MAX_ATTRS + 1];
    size_t u_dict_count;
} selective_show_view_t;

// ========== Basic Group Operations ==========

// G1 point addition
void g1_add(g1_point_t *result, const g1_point_t *p, const g1_point_t *q);

// G1 point multiplication
void g1_mul(g1_point_t *result, const g1_point_t *p, const scalar_t s);

// G1 point negation
void g1_neg(g1_point_t *result, const g1_point_t *p);

// G2 point addition
void g2_add(g2_point_t *result, const g2_point_t *p, const g2_point_t *q);

// G2 point multiplication
void g2_mul(g2_point_t *result, const g2_point_t *p, const scalar_t s);

// Pairing check: e(p_g1, q_g2) == e(r_g1, s_g2)
bool pairing_check(const g1_point_t *p_g1, const g2_point_t *q_g2,
                   const g1_point_t *r_g1, const g2_point_t *s_g2);

// ========== Hash Functions ==========

// Hash to G1 point (use hash_to_curve to avoid exposing logarithmic relations)
void hash_to_g1(g1_point_t *out, const byte *msg, size_t msg_len);

// Hash to scalar
void hash_to_scalar(scalar_t out, const byte *input, size_t input_len);

// Hash to challenge value (for Schnorr proof)
void hash_to_challenge(scalar_t out, const byte *tag, size_t tag_len,
                       const g1_point_t *base, const g1_point_t *y, const g1_point_t *R);

// Generate random scalar
void random_scalar(scalar_t out);

// Generate random scalar in mod r space (for ID allocation, ensure not zero)
void random_scalar_mod_r(scalar_t out);

// Scalar modular arithmetic
void scalar_mod(scalar_t out, const scalar_t in);

// Scalar inverse
void scalar_inv(scalar_t out, const scalar_t in);

// Scalar comparison
bool scalar_eq(const scalar_t a, const scalar_t b);
bool scalar_is_zero(const scalar_t a);

// ========== Accumulator Functions ==========

// Initialize accumulator
void setup_accumulator(system_params_t *params, issuer_keys_t *issuer_keys, size_t q);

// Cleanup accumulator resources
void cleanup_accumulator(system_params_t *params);

// Revoke ID (automatically expand capacity, fixed batch processing)
// Note: issuer_keys is not const, because need to modify pending_revokes and pending_count
void revoke_id(system_params_t *params, issuer_keys_t *issuer_keys, const scalar_t id);

// Timing statistics for non-membership witness generation parts
typedef struct {
    double compute_total_poly_time;  // compute_total_poly time (microseconds)
    double poly_eval_time;           // poly_eval time (microseconds)
    double gid_piid_time;            // Time to compute g_id and generate π_id (microseconds)
    double poly_div_time;            // poly_div_by_linear time (microseconds)
    double omega_loop_time;          // omega_id computation loop time (microseconds)
} gen_witness_timing_t;

// Generate non-membership witness (according to GenWitness algorithm in paper)
// Returns triple (ω_id, g_id, π_id)
// Note: Users don't need to know kappa, can use precomputed g1^{kappa^i}
void gen_witness(non_membership_witness_t *witness,
                 const system_params_t *params, const scalar_t id0);

// Generate non-membership witness (with timing version)
// timing: If not NULL, will record timing for each part
// use_optimized: If true, uses optimized compute_total_poly (tree merge)
void gen_witness_with_timing(non_membership_witness_t *witness,
                            const system_params_t *params, const scalar_t id0,
                            gen_witness_timing_t *timing, bool use_optimized);

// Compute total polynomial f_R(X) = ∏_{i=1}^t f_i(X) from all batch polynomial coefficients (public interface)
bool compute_total_poly(scalar_t *f_coeffs, size_t *f_count,
                       const system_params_t *params);

// Polynomial multiplication (public interface)
void poly_mul(scalar_t *result, size_t *result_count,
              const scalar_t *a, size_t a_count,
              const scalar_t *b, size_t b_count);

// Incremental computation of total polynomial: based on cached polynomial and new batch
// cached_poly: Cached total polynomial coefficients
// cached_count: Number of cached polynomial coefficients
// cached_batch_count: Number of processed batches
// new_batch_coeffs: New batch polynomial coefficients
// new_batch_count: Number of new batch polynomial coefficients
// result: Output result polynomial coefficients
// result_count: Number of output result polynomial coefficients
// max_result_size: Maximum capacity of result array
bool compute_total_poly_incremental(const scalar_t *cached_poly, size_t cached_count,
                                    size_t cached_batch_count,
                                    const scalar_t *new_batch_coeffs, size_t new_batch_count,
                                    scalar_t *result, size_t *result_count,
                                    size_t max_result_size);

// Generate non-membership witness (multithreaded version)
// Uses multithreading to parallelize omega_id computation for better performance
// num_threads: Number of threads, if 0 then automatically detects CPU core count
void gen_witness_multithread(non_membership_witness_t *witness,
                            const system_params_t *params, const scalar_t id0,
                            size_t num_threads);

// Legacy interface (maintained for compatibility, internally calls gen_witness)
void non_membership_witness(g1_point_t *omega, scalar_t v,
                           const system_params_t *params, const scalar_t id0);

// ========== Schnorr Proof ==========

// Generate Schnorr proof
// If r_commit is not NULL, use that value as commitment random number; otherwise generate new random number
void schnorr_prove(schnorr_proof_t *proof, const g1_point_t *base,
                   const g1_point_t *y, const scalar_t w, const byte *tag, size_t tag_len,
                   const scalar_t *r_commit);

// Verify Schnorr proof
bool schnorr_verify(const g1_point_t *base, const g1_point_t *y,
                    const schnorr_proof_t *proof, const byte *tag, size_t tag_len);

// Batch Schnorr proof: prove multiple relations all use same secret value r
// All proofs share same challenge value, thus proving they use same r
// bases, ys, ws are arrays, count is array length
// All proofs use the same r (specified via r_commit)
// Returns unified challenge value c (stored in first proof->s, but actual challenge value is in out_c)
void schnorr_batch_prove(schnorr_proof_t *proofs, const g1_point_t *bases,
                         const g1_point_t *ys, const scalar_t *ws, size_t count,
                         const byte *tag, size_t tag_len, const scalar_t r_commit,
                         scalar_t out_c);

// Verify batch Schnorr proof
bool schnorr_batch_verify(const g1_point_t *bases, const g1_point_t *ys,
                          const schnorr_proof_t *proofs, size_t count,
                          const byte *tag, size_t tag_len, const scalar_t c);

// ========== Core Functions ==========

// System initialization
void setup(system_params_t *params, issuer_keys_t *issuer_keys, size_t max_attrs, size_t q);

// Attribute commitment
void commit_attributes(g1_point_t *C, const system_params_t *params,
                       const scalar_t *m, size_t m_len);

// User generates request (Phase 1: Request)
// Generates user secret key sk_u and commitment M_1 = h_1^{sk_u}
void user_generate_request(scalar_t sk_u, g1_point_t *M1, schnorr_proof_t *pi_sk,
                           const system_params_t *params);

// Issuer verifies request and generates credential (Phase 2: Verification and Generation)
// Returns credential (id, A, e, exp), or false on failure
// validity_duration: lifetime in seconds, expiration time = current time + validity_duration
bool issuer_verify_and_generate(certificate_t *cert, system_params_t *params,
                                const issuer_keys_t *issuer_keys,
                                const g1_point_t *M1, const schnorr_proof_t *pi_sk,
                                const scalar_t *user_attrs, size_t user_attrs_len,
                                uint64_t validity_duration);

// User-side certificate verification (Phase 3: Verification)
// According to paper algorithm, user verifies signature (A, e) is correct
// sk_u: User's secret key (used to compute commitment)
bool user_verify_certificate(const system_params_t *params, const certificate_t *cert,
                             const scalar_t sk_u);

// Revoke certificate (when ID is known)
// Note: issuer_keys is not const, as pending_revokes and pending_count need to be modified
void revoke(system_params_t *params, issuer_keys_t *issuer_keys, const certificate_t *cert);

// Recover identifier from presentation transcript (according to paper algorithm)
// Input: g_r and g_2' (from malicious presentation transcript)
// Output: returns true and stores id in recovered_id if matching id found; otherwise returns false
// According to paper: issuer checks each candidate id, verifies g_2' == g_r^{id}
// Note: requires access to issued_ids in issuer_keys (confidential information)
bool recover_identifier_from_presentation(const system_params_t *params,
                                         const issuer_keys_t *issuer_keys,
                                         const g2_point_t *g_r, const g2_point_t *g2_p,
                                         scalar_t recovered_id);

// ========== Full Attribute Disclosure ==========

// Generate full attribute disclosure proof
void full_show_prove(full_show_view_t *view, const system_params_t *params,
                     const certificate_t *cert);

// Verify full attribute disclosure
bool full_show_verify(const system_params_t *params, const full_show_view_t *view);

// ========== Selective Disclosure ==========

// Generate selective disclosure proof
// sk_u: User secret key (used to correctly compute commitment C)
void selective_show_prove(selective_show_view_t *view, const system_params_t *params,
                          const certificate_t *cert, const scalar_t sk_u,
                          const int *J, size_t J_count);

// Verify selective disclosure
bool selective_show_verify(const system_params_t *params, const selective_show_view_t *view,
                           const scalar_t *disclosed_attrs, size_t disclosed_count);

// ========== Helper Functions ==========

// Convert scalar to byte array
void scalar_to_bytes(byte *out, const scalar_t s);

// Read scalar from byte array
void bytes_to_scalar(scalar_t out, const byte *in, size_t len);

// Print scalar (for debugging)
void print_scalar(const char *name, const scalar_t s);

// Print G1 point (for debugging)
void print_g1_point(const char *name, const g1_point_t *p);

#endif // ANON_CERT_H

