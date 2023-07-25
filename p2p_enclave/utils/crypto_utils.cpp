#include "crypto_utils.h"

using namespace std;

sgx_status_t key_verify(const sgx_ec256_public_t &pubkey, bool &valid) {
    sgx_status_t status;
    sgx_ecc_state_handle_t ecc_handle = nullptr;

    status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) {
        valid = false;
        goto cleanup;
    }

    int result;
    status = sgx_ecc256_check_point(&pubkey, ecc_handle, &result);
    if (status != SGX_SUCCESS) {
        valid = false;
        goto cleanup;
    }

    valid = (result != 0);

    cleanup:
    sgx_ecc256_close_context(ecc_handle);
    return status;
}

sgx_status_t key_generate(sgx_ec256_private_t &privkey, sgx_ec256_public_t &pubkey) {
    sgx_status_t status;
    sgx_ecc_state_handle_t ecc_handle = nullptr;

    status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    status = sgx_ecc256_create_key_pair(&privkey, &pubkey, ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    cleanup:
    sgx_ecc256_close_context(ecc_handle);
    return status;
}


sgx_status_t ecdh_shared_secret(sgx_ec256_private_t &privkey, sgx_ec256_public_t &pubkey,
                                sgx_ec256_dh_shared_t &shared) {
    sgx_status_t status;
    sgx_ecc_state_handle_t ecc_handle = nullptr;

    status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    status = sgx_ecc256_compute_shared_dhkey(&privkey, &pubkey, &shared, ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    cleanup:
    sgx_ecc256_close_context(ecc_handle);
    return status;
}

sgx_status_t ecdsa(const sgx_ec256_private_t &privkey, const uint8_t *data, uint32_t size,
                   sgx_ec256_signature_t &signature) {
    auto privk = const_cast<sgx_ec256_private_t *> (&privkey);
    sgx_status_t status;
    sgx_ecc_state_handle_t ecc_handle = nullptr;

    status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    status = sgx_ecdsa_sign(data, size, privk, &signature, ecc_handle);
    if (status != SGX_SUCCESS) {
        goto cleanup;
    }

    cleanup:
    sgx_ecc256_close_context(ecc_handle);
    return status;
}


sgx_status_t derive_key(key_derivation_type_t type,
                        const sgx_ec256_dh_shared_t &shared_secret,
                        sgx_cmac_128bit_key_t &derived_key) {

    sgx_status_t status;

    /* Perform an AES-128 CMAC on the little-endian form of Gabx using a block of 0x00 bytes for the key */
    vector<uint8_t> all_zero_cmac_key(SGX_CMAC_KEY_SIZE, 0);
    sgx_cmac_128bit_key_t key_derive_key;
    status = sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t *) all_zero_cmac_key.data(),
                                      (uint8_t *) &shared_secret, sizeof(sgx_ec256_dh_shared_t),
                                      (sgx_cmac_128bit_tag_t *) &key_derive_key);
    if (SGX_SUCCESS != status) {
        return status;
    }

    /* derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080) */
    uint8_t *derive_msg = nullptr;
    uint32_t derive_msg_length;

    switch (type) {
        case DERIVE_KEY_SMK:
            derive_msg = (uint8_t *) ("\x01SMK\x00\x80\x00");
            derive_msg_length = 7;
            break;
        case DERIVE_KEY_SK:
            derive_msg = (uint8_t *) ("\x01SK\x00\x80\x00");
            derive_msg_length = 6;
            break;
        case DERIVE_KEY_MK:
            derive_msg = (uint8_t *) ("\x01MK\x00\x80\x00");
            derive_msg_length = 6;
            break;
        case DERIVE_KEY_VK:
            derive_msg = (uint8_t *) ("\x01VK\x00\x80\x00");
            derive_msg_length = 6;
            break;
        default:
            return SGX_ERROR_INVALID_PARAMETER;
    }

    status = sgx_rijndael128_cmac_msg(&key_derive_key, derive_msg, derive_msg_length,
                                      (sgx_cmac_128bit_tag_t *) &derived_key);

    return status;
}

sgx_status_t get_filename(uint8_t* src, char* filename_buf) {
    sgx_sha256_hash_t hash;
    sgx_status_t status = SGX_SUCCESS;
    sgx_sha256_msg(src, 64, &hash);

    snprintf(filename_buf, FILENAME_BUF_LEN, "%s", BASE_FILENAME);

    for(int i = 0; i < SGX_SHA256_HASH_SIZE; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        strncat(filename_buf, buf, FILENAME_BUF_LEN - strlen(filename_buf) - 1);
    }

    strncat(filename_buf, ".txt", FILENAME_BUF_LEN - strlen(filename_buf) - 1);
    
    return status;
}