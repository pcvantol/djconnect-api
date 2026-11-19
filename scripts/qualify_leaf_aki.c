/* Offline OpenSSL policy probe only, NOT a Worker or complete verifier. */
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef struct {
    X509 *target;
    int allow_leaf_aki;
    int accepted_exception;
} PolicyState;

static int leaf_shape(X509 *certificate) {
    int first, second, basic_critical = -1, usage_critical = -1, eku_critical = -1;
    ASN1_OBJECT *nonce_oid = OBJ_txt2obj("1.2.840.113635.100.8.2", 1);
    EVP_PKEY *key = X509_get0_pubkey(certificate);
    char group[80]; size_t length = 0;
    if (!nonce_oid) return 0;
    first = X509_get_ext_by_OBJ(certificate, nonce_oid, -1);
    second = first < 0 ? -1 : X509_get_ext_by_OBJ(certificate, nonce_oid, first);
    ASN1_OBJECT_free(nonce_oid);
    BASIC_CONSTRAINTS *basic = X509_get_ext_d2i(certificate, NID_basic_constraints, &basic_critical, NULL);
    ASN1_BIT_STRING *usage = X509_get_ext_d2i(certificate, NID_key_usage, &usage_critical, NULL);
    EXTENDED_KEY_USAGE *eku = X509_get_ext_d2i(certificate, NID_ext_key_usage, &eku_critical, NULL);
    ASN1_OBJECT *expected_eku = OBJ_txt2obj("1.2.840.113635.100.4.24", 1);
    int result = basic && !basic->ca && basic_critical == 1 && usage && usage_critical == 1 &&
           ASN1_BIT_STRING_get_bit(usage, 0) && !ASN1_BIT_STRING_get_bit(usage, 5) &&
           eku && expected_eku && eku_critical == 0 && sk_ASN1_OBJECT_num(eku) == 1 &&
           OBJ_cmp(sk_ASN1_OBJECT_value(eku, 0), expected_eku) == 0 &&
           X509_check_ca(certificate) == 0 && first >= 0 && second < 0 &&
           X509_EXTENSION_get_critical(X509_get_ext(certificate, first)) == 0 &&
           key && EVP_PKEY_is_a(key, "EC") && EVP_PKEY_get_bits(key) == 256 &&
           EVP_PKEY_get_group_name(key, group, sizeof(group), &length) == 1 &&
           strcmp(group, "prime256v1") == 0;
    BASIC_CONSTRAINTS_free(basic); ASN1_BIT_STRING_free(usage);
    EXTENDED_KEY_USAGE_free(eku); ASN1_OBJECT_free(expected_eku);
    return result;
}

static int policy(int ok, X509_STORE_CTX *context) {
    if (ok) return 1;
    PolicyState *state = X509_STORE_CTX_get_app_data(context);
    X509 *current = X509_STORE_CTX_get_current_cert(context);
    if (state && state->allow_leaf_aki && !state->accepted_exception && current &&
        X509_STORE_CTX_get_error(context) == X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER &&
        X509_STORE_CTX_get_error_depth(context) == 0 && X509_cmp(current, state->target) == 0 &&
        X509_get_ext_by_NID(current, NID_authority_key_identifier, -1) < 0 && leaf_shape(current)) {
        state->accepted_exception = 1;
        X509_STORE_CTX_set_error(context, X509_V_OK);
        return 1;
    }
    return 0;
}

static X509 *read_certificate(const char *path) {
    BIO *input = BIO_new_file(path, "rb");
    if (!input) return NULL;
    X509 *certificate = PEM_read_bio_X509(input, NULL, NULL, NULL);
    BIO_free(input);
    return certificate;
}

int main(int argc, char **argv) {
    int result = 0, error = -1, depth = -1;
    X509 *root = NULL, *intermediate = NULL, *target = NULL;
    PolicyState state = {0};
    X509_STORE *store = NULL; X509_STORE_CTX *context = NULL;
    STACK_OF(X509) *untrusted = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int digest_length = 0;
    const unsigned char root_pin[32] = {
        0x1c,0xb9,0x82,0x3b,0xa2,0x8b,0xa6,0xad,0x2d,0x33,0xa0,0x06,0x94,0x1d,0xe2,0xae,
        0x4f,0x51,0x3e,0xf1,0xd4,0xe8,0x31,0xb9,0xf7,0xe0,0xfa,0x7b,0x62,0x42,0xc9,0x32
    };
    if (argc != 5 && argc != 6) goto done;
    if (strcmp(argv[4], "strict") && strcmp(argv[4], "leaf-aki")) goto done;
    state.allow_leaf_aki = strcmp(argv[4], "leaf-aki") == 0;
    root = read_certificate(argv[1]); intermediate = read_certificate(argv[2]); target = read_certificate(argv[3]);
    state.target = target;
    if (!root || !intermediate || !target || !leaf_shape(target)) goto done;
    if (!X509_digest(root, EVP_sha256(), digest, &digest_length) || digest_length != 32 ||
        CRYPTO_memcmp(root_pin, digest, 32)) goto done;
    store = X509_STORE_new(); context = X509_STORE_CTX_new(); untrusted = sk_X509_new_null();
    if (!store || !context || !untrusted || !X509_STORE_add_cert(store, root) ||
        !sk_X509_push(untrusted, intermediate) || !X509_STORE_CTX_init(context, store, target, untrusted)) goto done;
    X509_VERIFY_PARAM *parameters = X509_STORE_CTX_get0_param(context);
    if (!X509_VERIFY_PARAM_set_flags(parameters, X509_V_FLAG_X509_STRICT | X509_V_FLAG_CHECK_SS_SIGNATURE) ||
        !X509_VERIFY_PARAM_set_purpose(parameters, X509_PURPOSE_ANY)) goto done;
    X509_VERIFY_PARAM_set_depth(parameters, 1);
    if (argc == 6) {
        char *end = NULL; errno = 0;
        long long value = strtoll(argv[5], &end, 10);
        if (errno || !end || *end || value <= 0 || (long long)(time_t)value != value) goto done;
        X509_VERIFY_PARAM_set_time(parameters, (time_t)value);
    }
    X509_STORE_CTX_set_app_data(context, &state);
    X509_STORE_CTX_set_verify_cb(context, policy);
    result = X509_verify_cert(context) == 1;
    if (result) {
        STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(context);
        result = chain && sk_X509_num(chain) == 3 &&
            X509_cmp(sk_X509_value(chain, 0), target) == 0 &&
            X509_cmp(sk_X509_value(chain, 1), intermediate) == 0 &&
            X509_cmp(sk_X509_value(chain, 2), root) == 0;
    }
    error = X509_STORE_CTX_get_error(context); depth = X509_STORE_CTX_get_error_depth(context);
done:
    printf("{\"verified\":%s,\"allowed_missing_leaf_aki\":%s,\"error_code\":%d,\"error_depth\":%d}\n",
           result ? "true" : "false", state.accepted_exception ? "true" : "false", error, depth);
    X509_STORE_CTX_free(context); X509_STORE_free(store); sk_X509_free(untrusted);
    X509_free(root); X509_free(intermediate); X509_free(target);
    return result ? 0 : 1;
}
