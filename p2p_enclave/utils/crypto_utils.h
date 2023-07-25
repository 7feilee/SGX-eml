#ifndef SGX_EML_CRYPTO_UTILS_H
#define SGX_EML_CRYPTO_UTILS_H

#include <sgx_tcrypto.h>
#include <string>
#include <cstring>
#include <vector>

#define BASE_FILENAME "enclave_"
#define FILENAME_BUF_LEN 100

enum key_derivation_type_t {
    DERIVE_KEY_SMK,
    DERIVE_KEY_SK,
    DERIVE_KEY_MK,
    DERIVE_KEY_VK
};

sgx_status_t key_verify(const sgx_ec256_public_t &pubkey,
                        bool &valid);

sgx_status_t key_generate(sgx_ec256_private_t &privkey,
                          sgx_ec256_public_t &pubkey);

sgx_status_t ecdh_shared_secret(sgx_ec256_private_t &privkey,
                                sgx_ec256_public_t &pubkey,
                                sgx_ec256_dh_shared_t &shared);

sgx_status_t ecdsa(const sgx_ec256_private_t &privkey,
                   const uint8_t *data,
                   uint32_t size,
                   sgx_ec256_signature_t &signature);

sgx_status_t derive_key(key_derivation_type_t type,
                        const sgx_ec256_dh_shared_t &shared_secret,
                        sgx_cmac_128bit_key_t &derived_key);

sgx_status_t get_filename(uint8_t* src, char* filename_buf);


#endif //SGX_EML_CRYPTO_UTILS_H
