/*
 * anon_cert C implementation test program
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "anon_cert.h"

// Get current time (microseconds)
static double get_time_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000.0 + tv.tv_usec;
}

// Format time output (uniformly use milliseconds)
static void print_time(const char *name, double time_us) {
    printf("   %s: %.2f ms\n", name, time_us / 1000.0);
}

int main(int argc, char *argv[]) {
    (void)argc;  // Avoid unused parameter warning
    (void)argv;
    printf("========================================\n");
    printf("anon_cert C Implementation Performance Test\n");
    printf("========================================\n\n");
    
    double start_time, end_time;
    
    // 1. System initialization
    printf("1. System initialization...\n");
    start_time = get_time_us();
    system_params_t params;
    issuer_keys_t issuer_keys;
    // 3 user attributes, plus 3 fixed ones (id, sk_u, exp), total 6 hs needed
    // Therefore max_attrs should be at least 5 (hs[0..5])
    // Note: q is the number of precomputed powers g1^{kappa^i} (i = 0..q)
    // If R_count IDs are revoked, computing non-membership witness needs kappa powers up to (R_count - 1)
    // Theoretically q ≥ R_count - 1 is sufficient, but setting q = 200 provides safety margin
    // For 100 revoked IDs, theoretically q ≥ 99 is sufficient, q = 200 has about 2x margin
    setup(&params, &issuer_keys, 5, 200);  // max_attrs = 5, supports hs[0..5]
    end_time = get_time_us();
    print_time("Time", end_time - start_time);
    printf("   Done\n\n");
    
    // 1.5. Construct list of 100 revoked IDs (without executing real issue-revoke flow)
    printf("1.5. Constructing list of 100 revoked IDs...\n");
    start_time = get_time_us();
    for (int i = 0; i < 100; i++) {
        scalar_t test_id;
        memset(test_id, 0, 32);
        // Use different values as test IDs (avoid conflict with subsequent certificate IDs)
        // Use 1000 + i as ID value to ensure different from certificate IDs
        test_id[30] = (1000 + i) >> 8;
        test_id[31] = (1000 + i) & 0xff;
        revoke_id(&params, &issuer_keys, test_id);
    }
    end_time = get_time_us();
    print_time("Time", end_time - start_time);
    printf("   Done, revocation batch count: %zu, total revoked count: %zu\n\n", 
           params.batch_count, params.batch_count * params.rev_batch_size);
    
    // 2. Certificate issuance (using new interface)
    printf("2. Certificate issuance...\n");
    certificate_t cert;
    scalar_t user_attrs[3];
    scalar_t sk_u;  // User secret key
    
    // Set user attributes
    memset(user_attrs[0], 0, 32);
    user_attrs[0][31] = 11;  // m1 = 11
    memset(user_attrs[1], 0, 32);
    user_attrs[1][31] = 22;  // m2 = 22
    memset(user_attrs[2], 0, 32);
    user_attrs[2][31] = 33;  // m3 = 33
    
    // Phase 1: User generates request
    g1_point_t M1;
    schnorr_proof_t pi_sk;
    user_generate_request(sk_u, &M1, &pi_sk, &params);
    
    start_time = get_time_us();
    // Phase 2: Issuer verifies and generates credential
    // Set validity period to 1 year (365.25 days * 24 hours * 60 minutes * 60 seconds = 31557600 seconds)
    const uint64_t ONE_YEAR_SECONDS = 31557600ULL;
    bool issue_ok = issuer_verify_and_generate(&cert, &params, &issuer_keys, 
                                               &M1, &pi_sk, user_attrs, 3, ONE_YEAR_SECONDS);
    end_time = get_time_us();
    print_time("Time", end_time - start_time);
    
    if (!issue_ok) {
        fprintf(stderr, "Error: Certificate issuance failed\n");
        return 1;
    }
    
    printf("   Done, certificate ID: ");
    print_scalar("", cert.m[0]);
    printf("\n\n");
    
    // 3. User-side certificate verification (Phase 3)
    printf("3. User-side certificate verification...\n");
    start_time = get_time_us();
    bool ok = user_verify_certificate(&params, &cert, sk_u);
    end_time = get_time_us();
    print_time("Time", end_time - start_time);
    printf("   Result: %s\n\n", ok ? "Pass" : "Fail");
    
    if (!ok) {
        fprintf(stderr, "Error: Certificate verification failed\n");
        return 1;
    }
    
    // 4. Selective disclosure (disclose exp and first user attribute)
    // According to new structure: m[0]=id(hidden), m[1]=sk_u(hidden), m[2]=exp(disclosed), m[3]=user attribute 1(disclosed)
    printf("4. Selective disclosure (disclose exp and first user attribute)...\n");
    int J[] = {2, 3};  // Disclose exp (m[2]) and first user attribute (m[3])
    selective_show_view_t sel_view;
    
    start_time = get_time_us();
    selective_show_prove(&sel_view, &params, &cert, sk_u, J, 2);
    end_time = get_time_us();
    print_time("Proof generation time", end_time - start_time);
    
    scalar_t disclosed_attrs[2];
    memcpy(disclosed_attrs[0], cert.m[2], 32);  // exp
    memcpy(disclosed_attrs[1], cert.m[3], 32);  // First user attribute
    
    start_time = get_time_us();
    bool ok_sel = selective_show_verify(&params, &sel_view, disclosed_attrs, 2);
    end_time = get_time_us();
    print_time("Verification time", end_time - start_time);
    printf("   Verification result: %s\n\n", ok_sel ? "Pass" : "Fail");
    
    if (!ok_sel) {
        fprintf(stderr, "Error: Selective disclosure verification failed\n");
        // Don't return, continue testing other steps
    }
    
    // 5. Revoke certificate
    printf("5. Revoking certificate...\n");
    start_time = get_time_us();
    revoke(&params, &issuer_keys, &cert);
    end_time = get_time_us();
    print_time("Time", end_time - start_time);
    printf("   Done\n\n");
    
    // 5.1 Fill batch to rev_batch_size to trigger accumulator update
    // Note: pending_count is now in issuer_keys (confidential information)
    size_t pending = issuer_keys.pending_count;
    size_t need_fill = (pending == 0) ? 0 : (params.rev_batch_size - pending);
    if (need_fill > 0) {
        printf("5.1 Filling revocation batch (need to revoke %zu more placeholder IDs)...\n", need_fill);
        start_time = get_time_us();
        for (size_t i = 0; i < need_fill; i++) {
            scalar_t filler_id;
            memset(filler_id, 0, 32);
            uint64_t val = 2000 + i;  // Different from 1000+i above to avoid conflict
            for (int k = 7; k >= 0; k--) {
                filler_id[31 - k] = (byte)(val >> (k * 8));
            }
            revoke_id(&params, &issuer_keys, filler_id);
        }
        end_time = get_time_us();
        print_time("Time", end_time - start_time);
        printf("   Batch filling complete, current revocation batches: %zu, total revoked count: %zu\n\n", 
               params.batch_count, params.batch_count * params.rev_batch_size);
    }
    
    // 6. Try selective disclosure again after revocation (should fail)
    printf("6. Trying selective disclosure again after revocation...\n");
    selective_show_view_t sel_view2;
    
    start_time = get_time_us();
    selective_show_prove(&sel_view2, &params, &cert, sk_u, J, 2);
    end_time = get_time_us();
    print_time("Proof generation time", end_time - start_time);
    
    start_time = get_time_us();
    bool ok_sel2 = selective_show_verify(&params, &sel_view2, disclosed_attrs, 2);
    end_time = get_time_us();
    print_time("Verification time", end_time - start_time);
    printf("   Verification result: %s (expected: Fail)\n\n", ok_sel2 ? "Pass" : "Fail");
    
    if (ok_sel2) {
        fprintf(stderr, "Warning: Revoked certificate verification should fail but passed\n");
    }
    
    printf("========================================\n");
    printf("Performance test completed\n");
    printf("========================================\n");
    
    // Cleanup dynamically allocated memory
    cleanup_accumulator(&params);
    
    return 0;
}

