#ifndef SGX_EML_CRYPTO_UTILS_H
#define SGX_EML_CRYPTO_UTILS_H

#include <sgx_key_exchange.h>
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <vector>
#include <algorithm>
#include <fstream>

enum key_derivation_type_t {
    DERIVE_KEY_SMK,
    DERIVE_KEY_SK,
    DERIVE_KEY_MK,
    DERIVE_KEY_VK
};

void crypto_init();
void crypto_destroy();

bool key_verify(const sgx_ec256_public_t &pubkey);

bool key_generate(sgx_ec256_private_t &privkey,
                  sgx_ec256_public_t &pubkey);

bool ecdh_shared_secret(sgx_ec256_private_t &privkey,
                        sgx_ec256_public_t &pubkey,
                        sgx_ec256_dh_shared_t &shared);

bool derive_key(key_derivation_type_t type,
                const sgx_ec256_dh_shared_t &shared_secret,
                sgx_cmac_128bit_key_t &derived_key);

void bn2lebinpad(const BIGNUM *bn,
                 unsigned char *to,
                 size_t tolen);

bool ecdsa(const sgx_ec256_private_t &privkey,
           const uint8_t *data, uint32_t size,
           sgx_ec256_signature_t &signature);

bool compute_cmac_aes128(const sgx_cmac_128bit_key_t *p_key,
                         const uint8_t *p_src,
                         uint32_t src_len,
                         sgx_cmac_128bit_tag_t *p_mac);

bool calculate_sha256(const std::vector<uint8_t>& message,
                      sgx_sha256_hash_t *digest);
                    
bool sha256_digest(const unsigned char *msg,
                   size_t mlen, 
                   unsigned char digest[32]);

void handleErrors();

int aes_gcm_encrypt(uint8_t *key,
                    uint8_t *plaintext,
                    int plaintext_len,
                    uint8_t *ciphertext,
                    uint8_t *iv,
                    int iv_len,
                    uint8_t *aad,
                    int aad_len,
                    uint8_t *tag);

int aes_gcm_decrypt(uint8_t *key,
                    uint8_t *ciphertext, 
                    int ciphertext_len,
                    uint8_t *plaintext,
                    uint8_t *iv,
                    int iv_len,
                    uint8_t *aad,
                    int aad_len,
                    uint8_t *tag);

bool generateRSAKeyPair(const char* publicKeyFile,
                std::vector<uint8_t>& privateKeyBytes);


#endif //SGX_EML_CRYPTO_UTILS_H
