/*
 * Initialization performance test program
 * Tests initialization time with different attribute counts and accumulator capacities
 * Also tests performance of certificate issuance and verification phases
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include "anon_cert.h"

// Global file pointer for simultaneous file writing
static FILE *log_file = NULL;

// Function to print to both stdout and file
static int print_both(const char *format, ...) {
    va_list args;
    int ret;
    
    // Print to stdout
    va_start(args, format);
    ret = vprintf(format, args);
    va_end(args);
    
    // If file is open, also write to file
    if (log_file) {
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        fflush(log_file);  // Ensure immediate write
    }
    
    return ret;
}

// Redefine printf as print_both
#define printf print_both

// Get current time (microseconds)
static double get_time_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000.0 + tv.tv_usec;
}

// Test initialization performance for single attribute count
static double test_init_performance(size_t max_attrs, size_t q, int iterations) {
    double total_time = 0.0;
    
    for (int i = 0; i < iterations; i++) {
        // Use heap allocation to avoid stack overflow
        system_params_t *params = (system_params_t *)calloc(1, sizeof(system_params_t));
        issuer_keys_t *issuer_keys = (issuer_keys_t *)calloc(1, sizeof(issuer_keys_t));
        
        if (!params || !issuer_keys) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            if (params) free(params);
            if (issuer_keys) free(issuer_keys);
            return -1.0;
        }
        
        double start_time = get_time_us();
        setup(params, issuer_keys, max_attrs, q);
        double end_time = get_time_us();
        
        total_time += (end_time - start_time);
        
        // Cleanup resources
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
        
        // Free the structures themselves
        free(params);
        free(issuer_keys);
    }
    
    return total_time / iterations;  // Return average time
}

// Warmup function
static void warmup(size_t max_attrs, size_t q) {
    system_params_t *warmup_params = (system_params_t *)calloc(1, sizeof(system_params_t));
    issuer_keys_t *warmup_keys = (issuer_keys_t *)calloc(1, sizeof(issuer_keys_t));
    if (warmup_params && warmup_keys) {
        setup(warmup_params, warmup_keys, max_attrs, q);
        cleanup_accumulator(warmup_params);
        if (warmup_keys->pending_revokes) free(warmup_keys->pending_revokes);
        if (warmup_keys->issued_ids) free(warmup_keys->issued_ids);
        free(warmup_params);
        free(warmup_keys);
    }
}

// Test 1: Fixed accumulator capacity, test different attribute counts
static void test_varying_attrs() {
    printf("========================================\n");
    printf("Test 1: Fixed accumulator capacity, test different attribute counts\n");
    printf("========================================\n\n");
    
    const size_t q = 200;  // Fixed accumulator capacity
    const int iterations = 3;
    const int num_tests = 10;
    size_t attr_counts[num_tests];
    for (int i = 0; i < num_tests; i++) {
        attr_counts[i] = (i + 1) * 10;  // 10, 20, 30, ..., 100
    }
    
    printf("Test configuration:\n");
    printf("  - Accumulator capacity (q): %zu\n", q);
    printf("  - Iterations per attribute count: %d\n", iterations);
    printf("  - Attribute count range: 10 - 100 (step: 10)\n");
    printf("  - MAX_ATTRS = %d\n", MAX_ATTRS);
    printf("\n");
    
    printf("Warming up...\n");
    warmup(50, q);
    printf("Warmup complete\n\n");
    
    printf("Starting test...\n\n");
    printf("%-12s | %-15s | %-15s\n", "Attr Count", "Avg Time(ms)", "Total Time(ms)");
    printf("--------------------------------------------\n");
    
    double total_test_time = 0.0;
    for (int i = 0; i < num_tests; i++) {
        size_t max_attrs = attr_counts[i];
        
        double start_test = get_time_us();
        double avg_time = test_init_performance(max_attrs, q, iterations);
        double end_test = get_time_us();
        double total_time = end_test - start_test;
        
        total_test_time += total_time;
        
        printf("%-12zu | %-15.2f | %-15.2f\n", 
               max_attrs, avg_time / 1000.0, total_time / 1000.0);
    }
    
    printf("--------------------------------------------\n");
    printf("\nTest 1 completed!\n");
    printf("Total test time: %.2f ms (%.2f seconds)\n\n", 
           total_test_time / 1000.0, total_test_time / 1000000.0);
}

// Test certificate issuance and verification phase performance
typedef struct {
    double phase1_time;  // Phase 1: User generates request
    double phase2_time;  // Phase 2: Issuer verifies and generates credential
    double phase3_time;  // Phase 3: User-side certificate verification
} cert_perf_result_t;

static cert_perf_result_t test_cert_performance(size_t user_attrs_count, 
                                                  system_params_t *params, 
                                                  issuer_keys_t *issuer_keys, 
                                                  int iterations) {
    cert_perf_result_t result = {0.0, 0.0, 0.0};
    
    // Prepare user attribute array
    scalar_t *user_attrs = (scalar_t *)malloc(user_attrs_count * sizeof(scalar_t));
    if (!user_attrs) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return result;
    }
    
    // Initialize user attributes (use different values)
    for (size_t i = 0; i < user_attrs_count; i++) {
        memset(user_attrs[i], 0, 32);
        user_attrs[i][31] = (byte)(i + 1);  // Use different attribute values
    }
    
    const uint64_t ONE_YEAR_SECONDS = 31557600ULL;
    
    for (int iter = 0; iter < iterations; iter++) {
        scalar_t sk_u;
        g1_point_t M1;
        schnorr_proof_t pi_sk;
        certificate_t cert;
        
        // Phase 1: User generates request
        double start_phase1 = get_time_us();
        user_generate_request(sk_u, &M1, &pi_sk, params);
        double end_phase1 = get_time_us();
        result.phase1_time += (end_phase1 - start_phase1);
        
        // Phase 2: Issuer verifies and generates credential
        double start_phase2 = get_time_us();
        bool issue_ok = issuer_verify_and_generate(&cert, params, issuer_keys, 
                                                   &M1, &pi_sk, user_attrs, 
                                                   user_attrs_count, ONE_YEAR_SECONDS);
        double end_phase2 = get_time_us();
        result.phase2_time += (end_phase2 - start_phase2);
        
        if (!issue_ok) {
            fprintf(stderr, "Warning: Certificate issuance failed (attribute count: %zu, iteration: %d)\n", 
                   user_attrs_count, iter);
            continue;
        }
        
        // Phase 3: User-side certificate verification
        double start_phase3 = get_time_us();
        bool verify_ok = user_verify_certificate(params, &cert, sk_u);
        double end_phase3 = get_time_us();
        result.phase3_time += (end_phase3 - start_phase3);
        
        if (!verify_ok) {
            fprintf(stderr, "Warning: Certificate verification failed (attribute count: %zu, iteration: %d)\n", 
                   user_attrs_count, iter);
        }
    }
    
    // Calculate average
    result.phase1_time /= iterations;
    result.phase2_time /= iterations;
    result.phase3_time /= iterations;
    
    free(user_attrs);
    return result;
}

// Test 3: Certificate issuance and verification phase performance
static void test_cert_issue_verify() {
    printf("========================================\n");
    printf("Test 3: Certificate issuance and verification phase performance\n");
    printf("========================================\n\n");
    
    const size_t q = 200;  // Fixed accumulator capacity
    const int iterations = 3;  // Test each attribute count 3 times for average
    const int num_tests = 10;
    size_t user_attr_counts[num_tests];
    for (int i = 0; i < num_tests; i++) {
        user_attr_counts[i] = (i + 1) * 10;  // 10, 20, 30, ..., 100
    }
    
    printf("Test configuration:\n");
    printf("  - Accumulator capacity (q): %zu\n", q);
    printf("  - Iterations per attribute count: %d\n", iterations);
    printf("  - User attribute count range: 10 - 100 (step: 10)\n");
    printf("  - Note: max_attrs needs to be at least user attribute count + 3 (id, sk_u, exp)\n");
    printf("  - MAX_ATTRS = %d\n", MAX_ATTRS);
    printf("\n");
    
    // Initialize system (only once)
    printf("Initializing system...\n");
    system_params_t params;
    issuer_keys_t issuer_keys;
    // max_attrs needs to be large enough to support all user attributes + 3 fixed ones (id, sk_u, exp)
    size_t max_attrs = 100 + 3;  // Support up to 100 user attributes
    if (max_attrs > MAX_ATTRS) {
        max_attrs = MAX_ATTRS;
        printf("  Warning: max_attrs limited to MAX_ATTRS = %d\n", MAX_ATTRS);
    }
    setup(&params, &issuer_keys, max_attrs, q);
    printf("System initialization complete\n\n");
    
    printf("Warming up...\n");
    scalar_t warmup_sk_u;
    g1_point_t warmup_M1;
    schnorr_proof_t warmup_pi_sk;
    scalar_t warmup_attrs[1];
    memset(warmup_attrs[0], 0, 32);
    warmup_attrs[0][31] = 1;
    certificate_t warmup_cert;
    user_generate_request(warmup_sk_u, &warmup_M1, &warmup_pi_sk, &params);
    issuer_verify_and_generate(&warmup_cert, &params, &issuer_keys, 
                               &warmup_M1, &warmup_pi_sk, warmup_attrs, 1, 31557600ULL);
    user_verify_certificate(&params, &warmup_cert, warmup_sk_u);
    printf("Warmup complete\n\n");
    
    printf("Starting test...\n\n");
    printf("Phase description:\n");
    printf("  - Phase 1: User generates request (user_generate_request)\n");
    printf("  - Phase 2: Issuer verifies and generates credential (issuer_verify_and_generate)\n");
    printf("  - Phase 3: User-side certificate verification (user_verify_certificate)\n");
    printf("\n");
    printf("%-12s | %-15s | %-15s | %-15s\n", 
           "User Attrs", "Phase1(ms)", "Phase2(ms)", "Phase3(ms)");
    printf("------------------------------------------------------------\n");
    
    double total_test_time = 0.0;
    for (int i = 0; i < num_tests; i++) {
        size_t user_attrs_count = user_attr_counts[i];
        
        // Check if exceeds limit
        if (user_attrs_count + 3 > max_attrs) {
            printf("%-12zu | %-15s | %-15s | %-15s\n", 
                   user_attrs_count, "Skip(limit)", "Skip(limit)", "Skip(limit)");
            continue;
        }
        
        double start_test = get_time_us();
        cert_perf_result_t result = test_cert_performance(user_attrs_count, &params, 
                                                          &issuer_keys, iterations);
        double end_test = get_time_us();
        double total_time = end_test - start_test;
        
        total_test_time += total_time;
        
        printf("%-12zu | %-15.2f | %-15.2f | %-15.2f\n", 
               user_attrs_count, 
               result.phase1_time / 1000.0,
               result.phase2_time / 1000.0,
               result.phase3_time / 1000.0);
    }
    
    printf("------------------------------------------------------------\n");
    printf("\nTest 3 completed!\n");
    printf("Total test time: %.2f ms (%.2f seconds)\n\n", 
           total_test_time / 1000.0, total_test_time / 1000000.0);
    
    // Cleanup resources
    cleanup_accumulator(&params);
    if (issuer_keys.pending_revokes) free(issuer_keys.pending_revokes);
    if (issuer_keys.issued_ids) free(issuer_keys.issued_ids);
}

// Test selective disclosure performance
typedef struct {
    double prove_time;   // User-side proof generation time
    double verify_time;  // Verifier-side verification time
    double witness_time; // Non-membership witness generation time
} selective_perf_result_t;

static selective_perf_result_t test_selective_performance(size_t disclosed_count,
                                                          system_params_t *params,
                                                          const certificate_t *cert,
                                                          const scalar_t sk_u,
                                                          int iterations) {
    selective_perf_result_t result = {0.0, 0.0, 0.0};
    
    // Prepare disclosure attribute index array J
    // Note: index 0=id(hidden), 1=sk_u(hidden), 2=exp, 3 and later=user attributes
    // We select disclosed attributes starting from index 2 (including exp and user attributes)
    // However, according to selective_show_prove implementation, J ⊆ {2, 3, ..., l}, where l = cert->attr_count - 1
    int *J = (int *)malloc(disclosed_count * sizeof(int));
    if (!J) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return result;
    }
    
    // Prepare disclosed attribute values array
    // Order of disclosed_attrs must match order of J
    scalar_t *disclosed_attrs = (scalar_t *)malloc(disclosed_count * sizeof(scalar_t));
    if (!disclosed_attrs) {
        free(J);
        fprintf(stderr, "Error: Memory allocation failed\n");
        return result;
    }
    
    // Select disclosed attributes: start from index 2 (exp), then select user attributes
    // Note: cert->attr_count = user_attrs_count + 3
    // Index range: 0=id(hidden), 1=sk_u(hidden), 2=exp, 3..cert->attr_count-1=user attributes
    // According to selective_show_prove implementation: l = cert->attr_count - 1, J ⊆ {2, 3, ..., l}
    size_t l = cert->attr_count - 1;  // Maximum available index (excluding id)
    size_t max_disclosed = (l >= 2) ? (l - 2 + 1) : 0;  // Maximum number of attributes that can be disclosed (from index 2 to l)
    
    if (disclosed_count > max_disclosed) {
        fprintf(stderr, "Error: Disclosure count %zu exceeds available attribute range (max: %zu, l=%zu)\n", 
               disclosed_count, max_disclosed, l);
        free(J);
        free(disclosed_attrs);
        return result;
    }
    
    // disclosed_attrs[i] must correspond to attribute value at index J[i]
    // J ⊆ {2, 3, ..., l}
    for (size_t i = 0; i < disclosed_count; i++) {
        int attr_idx = (int)(2 + i);  // Start from index 2
        // Ensure index is within valid range [2, l]
        if (attr_idx < 2 || (size_t)attr_idx > l) {
            fprintf(stderr, "Error: Attribute index %d out of range [2, %zu]\n", attr_idx, l);
            free(J);
            free(disclosed_attrs);
            return result;
        }
        J[i] = attr_idx;
        memcpy(disclosed_attrs[i], cert->m[attr_idx], 32);
    }
    
    for (int iter = 0; iter < iterations; iter++) {
        selective_show_view_t view;
        memset(&view, 0, sizeof(selective_show_view_t));
        
        // Separately measure non-membership witness generation time
        scalar_t id0;
        memcpy(id0, cert->m[0], 32);  // Get certificate ID
        non_membership_witness_t witness;
        double start_witness = get_time_us();
        gen_witness(&witness, params, id0);
        double end_witness = get_time_us();
        result.witness_time += (end_witness - start_witness);
        
        // User side: generate proof
        double start_prove = get_time_us();
        selective_show_prove(&view, params, cert, sk_u, J, disclosed_count);
        double end_prove = get_time_us();
        result.prove_time += (end_prove - start_prove);
        
        // Check if proof was successfully generated (view.J_count should equal disclosed_count)
        if (view.J_count != disclosed_count) {
            fprintf(stderr, "Warning: Proof generation exception (disclosure count: %zu, J_count: %zu, iteration: %d)\n", 
                   disclosed_count, view.J_count, iter);
            continue;
        }
        
        // Verifier side: verify proof
        double start_verify = get_time_us();
        bool verify_ok = selective_show_verify(params, &view, disclosed_attrs, disclosed_count);
        double end_verify = get_time_us();
        result.verify_time += (end_verify - start_verify);
        
        if (!verify_ok) {
            // Verification failed, but doesn't affect performance test (time still recorded)
            // Note: This may indicate implementation issue, but performance test can still continue
        }
    }
    
    // Calculate average
    result.prove_time /= iterations;
    result.verify_time /= iterations;
    result.witness_time /= iterations;
    
    free(J);
    free(disclosed_attrs);
    return result;
}

// Test 4: Selective disclosure performance
static void test_selective_disclosure() {
    printf("========================================\n");
    printf("Test 4: Selective disclosure performance\n");
    printf("========================================\n\n");
    
    const size_t user_attrs_count = 30;  // Fixed user attribute count
    const size_t q = 1024;  // Accumulator capacity
    const int iterations = 3;  // Test each point 3 times for average
    
    // Test disclosure attribute counts: 5, 10, 15, 20, 25 (step: 5)
    const int num_tests = 5;
    size_t disclosed_counts[num_tests];
    for (int i = 0; i < num_tests; i++) {
        disclosed_counts[i] = (i + 1) * 5;  // 5, 10, 15, 20, 25
    }
    
    printf("Test configuration:\n");
    printf("  - User attribute count: %zu\n", user_attrs_count);
    printf("  - Accumulator capacity (q): %zu\n", q);
    printf("  - Iterations per disclosure count: %d\n", iterations);
    printf("  - Disclosure attribute count range: 5 - 25 (step: 5)\n");
    printf("  - Note: Total attributes = user attributes + 3 (id, sk_u, exp)\n");
    printf("  - MAX_ATTRS = %d\n", MAX_ATTRS);
    printf("\n");
    
    // Initialize system
    printf("Initializing system...\n");
    system_params_t params;
    issuer_keys_t issuer_keys;
    size_t max_attrs = user_attrs_count + 3;  // id, sk_u, exp + user attributes
    if (max_attrs > MAX_ATTRS) {
        max_attrs = MAX_ATTRS;
        printf("  Warning: max_attrs limited to MAX_ATTRS = %d\n", MAX_ATTRS);
    }
    setup(&params, &issuer_keys, max_attrs, q);
    printf("System initialization complete\n\n");
    
    // Issue a certificate for testing
    printf("Issuing test certificate...\n");
    scalar_t *user_attrs = (scalar_t *)malloc(user_attrs_count * sizeof(scalar_t));
    if (!user_attrs) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        cleanup_accumulator(&params);
        if (issuer_keys.pending_revokes) free(issuer_keys.pending_revokes);
        if (issuer_keys.issued_ids) free(issuer_keys.issued_ids);
        return;
    }
    
    // Initialize user attributes
    for (size_t i = 0; i < user_attrs_count; i++) {
        memset(user_attrs[i], 0, 32);
        user_attrs[i][31] = (byte)(i + 1);
    }
    
    scalar_t sk_u;
    g1_point_t M1;
    schnorr_proof_t pi_sk;
    certificate_t cert;
    const uint64_t ONE_YEAR_SECONDS = 31557600ULL;
    
    user_generate_request(sk_u, &M1, &pi_sk, &params);
    bool issue_ok = issuer_verify_and_generate(&cert, &params, &issuer_keys, 
                                               &M1, &pi_sk, user_attrs, 
                                               user_attrs_count, ONE_YEAR_SECONDS);
    if (!issue_ok) {
        fprintf(stderr, "Error: Certificate issuance failed\n");
        free(user_attrs);
        cleanup_accumulator(&params);
        if (issuer_keys.pending_revokes) free(issuer_keys.pending_revokes);
        if (issuer_keys.issued_ids) free(issuer_keys.issued_ids);
        return;
    }
    
    // Verify certificate is correct
    bool cert_verify_ok = user_verify_certificate(&params, &cert, sk_u);
    if (!cert_verify_ok) {
        fprintf(stderr, "Error: Certificate verification failed, cannot continue test\n");
        free(user_attrs);
        cleanup_accumulator(&params);
        if (issuer_keys.pending_revokes) free(issuer_keys.pending_revokes);
        if (issuer_keys.issued_ids) free(issuer_keys.issued_ids);
        return;
    }
    printf("Certificate issuance complete, certificate verification passed\n");
    printf("  Certificate attribute count: %zu\n", cert.attr_count);
    printf("\n");
    
    // Warmup (using same method as test_main.c)
    printf("Warming up...\n");
    int warmup_J[] = {2, 3};  // Only disclose exp and first user attribute
    scalar_t warmup_attrs[2];
    memcpy(warmup_attrs[0], cert.m[2], 32);  // exp
    memcpy(warmup_attrs[1], cert.m[3], 32);  // First user attribute
    selective_show_view_t warmup_view;
    selective_show_prove(&warmup_view, &params, &cert, sk_u, warmup_J, 2);
    bool warmup_ok = selective_show_verify(&params, &warmup_view, warmup_attrs, 2);
    if (!warmup_ok) {
        // Warmup failed, but continue test (may be implementation issue, doesn't affect performance test)
    }
    printf("Warmup complete\n\n");
    
    // Revoke 100 IDs (for testing performance with large number of revoked IDs)
    printf("Revoking 100 IDs...\n");
    double revoke_start = get_time_us();
    for (int i = 0; i < 100; i++) {
        scalar_t test_id;
        memset(test_id, 0, 32);
        // Use different values as test IDs (avoid conflict with certificate IDs)
        // Use 10000 + i as ID value to ensure different from certificate IDs
        uint32_t id_value = 10000 + i;
        for (int j = 0; j < 4; j++) {
            test_id[28 + j] = (byte)((id_value >> (j * 8)) & 0xff);
        }
        revoke_id(&params, &issuer_keys, test_id);
    }
    double revoke_end = get_time_us();
    printf("Revocation complete, time: %.2f ms\n", (revoke_end - revoke_start) / 1000.0);
    
    // Compute current number of revoked IDs
    size_t total_revoked = params.batch_count * params.rev_batch_size + issuer_keys.pending_count;
    printf("Current revoked ID count: %zu (batches: %zu, per batch: %zu, pending: %zu)\n\n", 
           total_revoked, params.batch_count, params.rev_batch_size, issuer_keys.pending_count);
    
    printf("Starting test...\n\n");
    printf("Phase description:\n");
    printf("  - User side: Generate selective disclosure proof (selective_show_prove)\n");
    printf("  - Verifier side: Verify selective disclosure proof (selective_show_verify)\n");
    printf("  - Witness generation: Generate non-membership witness (gen_witness)\n");
    printf("\n");
    printf("%-12s | %-15s | %-15s | %-15s | %-15s | %-15s\n", 
           "Disclose#", "User(ms)", "Verify(ms)", "Witness(ms)", "Revoked#", "Batch#");
    printf("--------------------------------------------------------------------------------------------\n");
    
    double total_test_time = 0.0;
    for (int i = 0; i < num_tests; i++) {
        size_t disclosed_count = disclosed_counts[i];
        
        // Check if exceeds limit (total attributes = user_attrs_count + 3)
        if (disclosed_count > user_attrs_count + 1) {  // +1 because can start from index 2
            size_t current_revoked = params.batch_count * params.rev_batch_size + issuer_keys.pending_count;
            printf("%-12zu | %-15s | %-15s | %-15s | %-15zu | %-15zu\n", 
                   disclosed_count, "Skip(limit)", "Skip(limit)", "Skip(limit)", current_revoked, issuer_keys.pending_count);
            continue;
        }
        
        // Recompute number of revoked IDs and IDs in current revocation group before each test
        size_t current_revoked = params.batch_count * params.rev_batch_size + issuer_keys.pending_count;
        size_t pending_count = issuer_keys.pending_count;
        
        double start_test = get_time_us();
        selective_perf_result_t result = test_selective_performance(disclosed_count, &params, 
                                                                     &cert, sk_u, iterations);
        double end_test = get_time_us();
        double total_time = end_test - start_test;
        
        total_test_time += total_time;
        
        printf("%-12zu | %-15.2f | %-15.2f | %-15.2f | %-15zu | %-15zu\n", 
               disclosed_count,
               result.prove_time / 1000.0,
               result.verify_time / 1000.0,
               result.witness_time / 1000.0,
               current_revoked,
               pending_count);
    }
    
    printf("--------------------------------------------------------------------------------------------\n");
    printf("\nTest 4 completed!\n");
    printf("Total test time: %.2f ms (%.2f seconds)\n\n", 
           total_test_time / 1000.0, total_test_time / 1000000.0);
    
    // Cleanup resources
    free(user_attrs);
    cleanup_accumulator(&params);
    if (issuer_keys.pending_revokes) free(issuer_keys.pending_revokes);
    if (issuer_keys.issued_ids) free(issuer_keys.issued_ids);
}

// Test 5: Witness generation performance with different revoked ID counts
static void test_selective_with_varying_revoked() {
    printf("========================================\n");
    printf("Test 5: Witness generation performance with different revoked ID counts\n");
    printf("========================================\n\n");
    
    const size_t user_attrs_count = 30;  // Fixed user attribute count
    const size_t q = 12000;  // Accumulator capacity
    const int iterations = 3;  // Test each point 3 times for average
    
    // Test revoked ID counts: 1000, 2000, 3000, ..., 10000 (step: 1000)
    const int num_tests = 10;
    size_t revoked_counts[num_tests];
    for (int i = 0; i < num_tests; i++) {
        revoked_counts[i] = (i + 1) * 1000;  // 1000, 2000, 3000, ..., 10000
    }
    
    printf("Test configuration:\n");
    printf("  - User attribute count: %zu\n", user_attrs_count);
    printf("  - Accumulator capacity (q): %zu\n", q);
    printf("  - Iterations per revocation count: %d\n", iterations);
    printf("  - Revoked ID count range: 1000 - 10000 (step: 1000)\n");
    printf("  - MAX_ATTRS = %d\n", MAX_ATTRS);
    printf("\n");
    
    // Initialize system
    printf("Initializing system...\n");
    system_params_t params;
    issuer_keys_t issuer_keys;
    size_t max_attrs = user_attrs_count + 3;  // id, sk_u, exp + user attributes
    if (max_attrs > MAX_ATTRS) {
        max_attrs = MAX_ATTRS;
        printf("  Warning: max_attrs limited to MAX_ATTRS = %d\n", MAX_ATTRS);
    }
    setup(&params, &issuer_keys, max_attrs, q);
    printf("System initialization complete\n\n");
    
    // Issue a certificate for testing
    printf("Issuing test certificate...\n");
    scalar_t *user_attrs = (scalar_t *)malloc(user_attrs_count * sizeof(scalar_t));
    if (!user_attrs) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        cleanup_accumulator(&params);
        if (issuer_keys.pending_revokes) free(issuer_keys.pending_revokes);
        if (issuer_keys.issued_ids) free(issuer_keys.issued_ids);
        return;
    }
    
    // Initialize user attributes
    for (size_t i = 0; i < user_attrs_count; i++) {
        memset(user_attrs[i], 0, 32);
        user_attrs[i][31] = (byte)(i + 1);
    }
    
    scalar_t sk_u;
    g1_point_t M1;
    schnorr_proof_t pi_sk;
    certificate_t cert;
    const uint64_t ONE_YEAR_SECONDS = 31557600ULL;
    
    user_generate_request(sk_u, &M1, &pi_sk, &params);
    bool issue_ok = issuer_verify_and_generate(&cert, &params, &issuer_keys, 
                                               &M1, &pi_sk, user_attrs, 
                                               user_attrs_count, ONE_YEAR_SECONDS);
    if (!issue_ok) {
        fprintf(stderr, "Error: Certificate issuance failed\n");
        free(user_attrs);
        cleanup_accumulator(&params);
        if (issuer_keys.pending_revokes) free(issuer_keys.pending_revokes);
        if (issuer_keys.issued_ids) free(issuer_keys.issued_ids);
        return;
    }
    
    // Verify certificate is correct
    bool cert_verify_ok = user_verify_certificate(&params, &cert, sk_u);
    if (!cert_verify_ok) {
        fprintf(stderr, "Error: Certificate verification failed, cannot continue test\n");
        free(user_attrs);
        cleanup_accumulator(&params);
        if (issuer_keys.pending_revokes) free(issuer_keys.pending_revokes);
        if (issuer_keys.issued_ids) free(issuer_keys.issued_ids);
        return;
    }
    printf("Certificate issuance complete, certificate verification passed\n");
    printf("  Certificate attribute count: %zu\n\n", cert.attr_count);
    
    printf("Starting test...\n\n");
    printf("Phase description:\n");
    printf("  - Witness generation: Generate non-membership witness (gen_witness)\n");
    printf("\n");
    printf("%-12s | %-15s | %-15s | %-15s\n", 
           "Revoked#", "Witness(ms)", "Revoked#", "Batch#");
    printf("----------------------------------------------------------------------------\n");
    
    // Get certificate ID for testing
    scalar_t id0;
    memcpy(id0, cert.m[0], 32);
    
    double total_test_time = 0.0;
    for (int i = 0; i < num_tests; i++) {
        size_t target_revoked = revoked_counts[i];
        
        // Compute number of IDs that need to be revoked
        size_t current_revoked = params.batch_count * params.rev_batch_size + issuer_keys.pending_count;
        size_t need_revoke = (target_revoked > current_revoked) ? (target_revoked - current_revoked) : 0;
        
        // Revoke IDs to target count
        if (need_revoke > 0) {
            for (size_t j = 0; j < need_revoke; j++) {
                scalar_t test_id;
                memset(test_id, 0, 32);
                // Use different values as test IDs (avoid conflict with certificate IDs)
                uint32_t id_value = 20000 + current_revoked + j;
                for (int k = 0; k < 4; k++) {
                    test_id[28 + k] = (byte)((id_value >> (k * 8)) & 0xff);
                }
                revoke_id(&params, &issuer_keys, test_id);
            }
        }
        
        // Recompute current number of revoked IDs
        size_t final_revoked = params.batch_count * params.rev_batch_size + issuer_keys.pending_count;
        size_t pending_count = issuer_keys.pending_count;
        
        // Test witness generation performance
        double witness_time_total = 0.0;
        
        for (int iter = 0; iter < iterations; iter++) {
            non_membership_witness_t witness;
            double start_witness = get_time_us();
            gen_witness(&witness, &params, id0);
            double end_witness = get_time_us();
            witness_time_total += (end_witness - start_witness);
        }
        
        // Calculate average
        double witness_time_avg = witness_time_total / iterations;
        
        total_test_time += witness_time_total;
        
        printf("%-12zu | %-15.2f | %-15zu | %-15zu\n", 
               target_revoked,
               witness_time_avg / 1000.0,
               final_revoked,
               pending_count);
    }
    
    printf("----------------------------------------------------------------------------\n");
    printf("\nTest 5 completed!\n");
    printf("Total test time: %.2f ms (%.2f seconds)\n\n", 
           total_test_time / 1000.0, total_test_time / 1000000.0);
    
    // Cleanup resources
    free(user_attrs);
    cleanup_accumulator(&params);
    if (issuer_keys.pending_revokes) free(issuer_keys.pending_revokes);
    if (issuer_keys.issued_ids) free(issuer_keys.issued_ids);
}

// Test 2: Fixed attribute count, test different accumulator capacities
static void test_varying_q() {
    printf("========================================\n");
    printf("Test 2: Fixed attribute count, test different accumulator capacities\n");
    printf("========================================\n\n");
    
    const size_t max_attrs = 30;  // Fixed attribute count
    const int iterations = 3;
    const int num_tests = 10;
    size_t q_values[num_tests];
    for (int i = 0; i < num_tests; i++) {
        q_values[i] = (i + 1) * 200;  // 200, 400, 600, ..., 2000
    }
    
    printf("Test configuration:\n");
    printf("  - Attribute count (max_attrs): %zu\n", max_attrs);
    printf("  - Iterations per accumulator capacity: %d\n", iterations);
    printf("  - Accumulator capacity range: 200 - 2000 (step: 200)\n");
    printf("  - MAX_ATTRS = %d\n", MAX_ATTRS);
    printf("\n");
    
    printf("Warming up...\n");
    warmup(max_attrs, 1000);
    printf("Warmup complete\n\n");
    
    printf("Starting test...\n\n");
    printf("%-12s | %-15s | %-15s\n", "Accum Capacity", "Avg Time(ms)", "Total Time(ms)");
    printf("--------------------------------------------\n");
    
    double total_test_time = 0.0;
    for (int i = 0; i < num_tests; i++) {
        size_t q = q_values[i];
        
        double start_test = get_time_us();
        double avg_time = test_init_performance(max_attrs, q, iterations);
        double end_test = get_time_us();
        double total_time = end_test - start_test;
        
        total_test_time += total_time;
        
        printf("%-12zu | %-15.2f | %-15.2f\n", 
               q, avg_time / 1000.0, total_time / 1000.0);
    }
    
    printf("--------------------------------------------\n");
    printf("\nTest 2 completed!\n");
    printf("Total test time: %.2f ms (%.2f seconds)\n\n", 
           total_test_time / 1000.0, total_test_time / 1000000.0);
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    // Open log file
    char log_filename[256];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    snprintf(log_filename, sizeof(log_filename), 
             "test_init_perf_%04d%02d%02d_%02d%02d%02d.log",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    
    log_file = fopen(log_filename, "w");
    if (log_file) {
        fprintf(stderr, "Log file: %s\n", log_filename);
    } else {
        fprintf(stderr, "Warning: Cannot open log file %s, output only to stdout\n", log_filename);
    }
    
    printf("========================================\n");
    printf("Initialization Performance Test\n");
    printf("========================================\n\n");
    
    // Execute test 1: Fixed accumulator capacity, test different attribute counts
    test_varying_attrs();
    
    // Execute test 2: Fixed attribute count, test different accumulator capacities
    test_varying_q();
    
    // Execute test 3: Certificate issuance and verification phase performance
    test_cert_issue_verify();
    
    // Execute test 4: Selective disclosure performance
    test_selective_disclosure();
    
    // Execute test 5: Selective disclosure performance with different revoked ID counts
    test_selective_with_varying_revoked();
    
    printf("========================================\n");
    printf("All tests completed!\n");
    printf("========================================\n");
    
    // Close log file
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
        fprintf(stderr, "\nResults saved to: %s\n", log_filename);
    }
    
    return 0;
}

