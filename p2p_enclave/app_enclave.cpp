#include <tlibc/mbusafecrt.h>
#include "sgx_tprotected_fs.h"
#include "p2p_enclave_t.h"
#include "sp_routines.h"
#include <cstdio>
#include <cstring>
#include "utils/crypto_utils.h"

#define COUNTER_LENGTH_IN_BYTES 16

using namespace std;
extern ra_secret_t secret;
sgx_ec_key_128bit_t final_key;
static const char* filename = "sp_secret.txt";

sgx_status_t ecall_isv_init_share_key(sgx_ra_context_t ctx, sgx_sha256_hash_t *hash) {
    sgx_status_t status = SGX_SUCCESS;

    status = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &final_key);
    check_sgx_status(status);

    /* Now generate a SHA hash */
    status = sgx_sha256_msg((uint8_t *) final_key, sizeof(sgx_ec_key_128bit_t) , hash);

    return status;    
}

sgx_status_t ecall_sp_init_share_key(sgx_sha256_hash_t *hash) {
    sgx_status_t status = SGX_SUCCESS;


    status = derive_key(DERIVE_KEY_SK, secret.shared_secret, final_key);
    check_sgx_status(status);

    /* Now generate a SHA hash */
    status = sgx_sha256_msg((uint8_t *) final_key, sizeof(sgx_ec_key_128bit_t) , hash);

    return status;
}


/*
 * Encrypt & Decrypt using AES-CTR-128
 */
sgx_status_t aes_ctr_128_encrypt(uint8_t *buffer, uint32_t length, uint8_t nonce[COUNTER_LENGTH_IN_BYTES]) {
    uint8_t counter[COUNTER_LENGTH_IN_BYTES];

    sgx_status_t status = sgx_read_rand(counter, COUNTER_LENGTH_IN_BYTES);
    check_sgx_status(status);


    memcpy_s((void *) nonce, COUNTER_LENGTH_IN_BYTES, counter, COUNTER_LENGTH_IN_BYTES);
    uint8_t *ciphertext = (uint8_t *) malloc(length);

    status = sgx_aes_ctr_encrypt(&final_key, buffer, length, counter, COUNTER_LENGTH_IN_BYTES * 8, ciphertext);
    check_sgx_status(status);

    memcpy_s((void *) buffer, length, ciphertext, length);

    memset((void *) ciphertext, 0, length);

    return status;
}

sgx_status_t aes_ctr_128_decrypt(uint8_t *buffer, uint32_t length, uint8_t nonce[COUNTER_LENGTH_IN_BYTES]) {
    uint8_t counter[COUNTER_LENGTH_IN_BYTES];
    memcpy_s(counter, COUNTER_LENGTH_IN_BYTES, (void *) nonce, COUNTER_LENGTH_IN_BYTES);

    uint8_t *plaintext = (uint8_t *) malloc(length);

    sgx_status_t status = sgx_aes_ctr_decrypt(&final_key, buffer, length, counter, COUNTER_LENGTH_IN_BYTES * 8,
                                              plaintext);
    check_sgx_status(status);

    memcpy_s((void *) buffer, length, plaintext, length);
    memset((void *) plaintext, 0, length);

    return status;
}

sgx_status_t write_secret_to_file(const char* filename, unsigned char* secret, size_t secret_len) {
    SGX_FILE* fp = sgx_fopen(filename, "w", NULL);
    if (fp == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }

    size_t written = sgx_fwrite(secret, 1, secret_len, fp);
    sgx_fclose(fp);

    if (written != secret_len) {
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

sgx_status_t ecall_isv_put_secret(sgx_ra_context_t context, const uint8_t* p_secret, const uint8_t* p_gcm_mac){
    sgx_status_t status = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;
    uint8_t* g_secret = (uint8_t*) malloc(SAMPLE_PAYLOAD_SIZE);
    status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    check_sgx_status(status);
    uint8_t aes_gcm_iv[12] = {0};

    status = sgx_rijndael128GCM_decrypt(&sk_key,
                                        p_secret,
                                        SAMPLE_PAYLOAD_SIZE,
                                        &g_secret[0],
                                        &aes_gcm_iv[0],
                                        12,
                                        NULL,
                                        0,
                                        (const sgx_aes_gcm_128bit_tag_t *)
                                        (p_gcm_mac));
    
    check_sgx_status(status);

    status = write_secret_to_file(filename, g_secret, SAMPLE_PAYLOAD_SIZE);
    check_sgx_status(status);
    memset((void *) g_secret, 0, SAMPLE_PAYLOAD_SIZE);

    return status;
}

sgx_status_t ecall_get_sp_secret(uint8_t* p_secret){
    SGX_FILE* fp = sgx_fopen_auto_key(filename, "rb");

    if (fp == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }

    // Assuming the file contains exactly 16 bytes.
    size_t readsize = sgx_fread(p_secret, 1, 16, fp);

    sgx_fclose(fp);

    if (readsize != 16) {
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}
