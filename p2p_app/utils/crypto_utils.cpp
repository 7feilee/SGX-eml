#include "crypto_utils.h"

using namespace std;

void crypto_init ()
{
	/* Load error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load digest and ciphers */
	OpenSSL_add_all_algorithms();
}

void crypto_destroy ()
{
	EVP_cleanup();

	CRYPTO_cleanup_all_ex_data();

	ERR_free_strings();
}

bool key_verify(const sgx_ec256_public_t& pubkey) {
    bool valid = false;
    EC_GROUP* curve = nullptr;
    EC_POINT* pub_point = nullptr;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;

    curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (curve == nullptr) {
        return false;
    }

    pub_point = EC_POINT_new(curve);
    if (pub_point == nullptr) {
        EC_GROUP_free(curve);
        return false;
    }

    bn_x = BN_lebin2bn(pubkey.gx, SGX_ECP256_KEY_SIZE, nullptr);
    bn_y = BN_lebin2bn(pubkey.gy, SGX_ECP256_KEY_SIZE, nullptr);
    if (bn_x == nullptr || bn_y == nullptr) {
        EC_POINT_free(pub_point);
        EC_GROUP_free(curve);
        if(bn_x) BN_free(bn_x);
        if(bn_y) BN_free(bn_y);
        return false;
    }

    if (EC_POINT_set_affine_coordinates_GFp(curve, pub_point, bn_x, bn_y, nullptr) != 1) {
        EC_POINT_free(pub_point);
        EC_GROUP_free(curve);
        BN_free(bn_x);
        BN_free(bn_y);
        return false;
    }

    if (EC_POINT_is_on_curve(curve, pub_point, nullptr) != 1) {
        EC_POINT_free(pub_point);
        EC_GROUP_free(curve);
        BN_free(bn_x);
        BN_free(bn_y);
        return false;
    }

    // Clean up memory
    EC_POINT_free(pub_point);
    EC_GROUP_free(curve);
    BN_free(bn_x);
    BN_free(bn_y);

    return true;
}

bool key_generate(sgx_ec256_private_t &privkey, sgx_ec256_public_t &pubkey) {
    EC_KEY *key = nullptr;
    const EC_POINT *pub_point = nullptr;
    const BIGNUM *priv_bn = nullptr;
    BIGNUM *pub_bn_x = nullptr, *pub_bn_y = nullptr;

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == nullptr) {
        // error handling
        return false;
    }

    if (EC_KEY_generate_key(key) != 1) {
        // error handling
        EC_KEY_free(key);
        return false;
    }

    /* Extract private key */
    priv_bn = EC_KEY_get0_private_key(key);

    bn2lebinpad(priv_bn, (unsigned char*)privkey.r, sizeof(privkey.r));

    /* Extract public key */
    pub_point = EC_KEY_get0_public_key(key);
    pub_bn_x = BN_new();
    pub_bn_y = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key), pub_point, pub_bn_x, pub_bn_y, nullptr) != 1) {
        // error handling
        BN_free(pub_bn_x);
        BN_free(pub_bn_y);
        EC_KEY_free(key);
        return false;
    }

    bn2lebinpad(pub_bn_x, (unsigned char*)pubkey.gx, sizeof(pubkey.gx));

    bn2lebinpad(pub_bn_y, (unsigned char*)pubkey.gy, sizeof(pubkey.gy));

    /* Clean up */
    BN_free(pub_bn_x);
    BN_free(pub_bn_y);
    EC_KEY_free(key);

    return true;
}

bool ecdh_shared_secret(sgx_ec256_private_t &privkey, sgx_ec256_public_t &pubkey,
                        sgx_ec256_dh_shared_t &shared) {
    BIGNUM *priv_bn = NULL, *pub_bn_x = NULL, *pub_bn_y = NULL;
    EC_KEY *priv_key = NULL, *pub_key = NULL;
    EC_POINT *pub_point = NULL;
    EC_GROUP *group = NULL;
    int len;
    bool success = false;

    // Convert private key to OpenSSL BIGNUM
    priv_bn = BN_lebin2bn(privkey.r, sizeof(privkey.r), NULL);
    if (!priv_bn) goto cleanup;

    // Convert public key to OpenSSL BIGNUM
    pub_bn_x = BN_lebin2bn(pubkey.gx, sizeof(pubkey.gx), NULL);
    pub_bn_y = BN_lebin2bn(pubkey.gy, sizeof(pubkey.gy), NULL);
    if (!pub_bn_x || !pub_bn_y) goto cleanup;

    // Create new EC_KEY objects
    priv_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    pub_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!priv_key || !pub_key) goto cleanup;

    // Set private key
    if (!EC_KEY_set_private_key(priv_key, priv_bn)) goto cleanup;

    // Set public key
    group = (EC_GROUP*)EC_KEY_get0_group(pub_key);
    pub_point = EC_POINT_new(group);
    if (!EC_POINT_set_affine_coordinates_GFp(group, pub_point, pub_bn_x, pub_bn_y, NULL)) goto cleanup;
    if (!EC_KEY_set_public_key(pub_key, pub_point)) goto cleanup;

     // Compute shared secret
    len = ECDH_compute_key(shared.s, sizeof(shared.s), EC_KEY_get0_public_key(pub_key), priv_key, NULL);
    if (len <= 0) goto cleanup;

    // Convert shared secret to little endian
    reverse(shared.s, shared.s + sizeof(shared.s));
    success = true;

cleanup:
    BN_free(priv_bn);
    BN_free(pub_bn_x);
    BN_free(pub_bn_y);
    EC_KEY_free(priv_key);
    EC_KEY_free(pub_key);
    EC_POINT_free(pub_point);
    
    return success;
}

bool derive_key(key_derivation_type_t type, const sgx_ec256_dh_shared_t &shared_secret, sgx_cmac_128bit_key_t &derived_key) {
    sgx_status_t status;

    // Perform an AES-128 CMAC on the little-endian form of Gabx using a block of 0x00 bytes for the key
    sgx_cmac_128bit_key_t all_zero_cmac_key;
    memset(all_zero_cmac_key, 0, sizeof(all_zero_cmac_key));
    sgx_cmac_128bit_key_t key_derive_key;
    if (!compute_cmac_aes128(&all_zero_cmac_key, (uint8_t*)&shared_secret, sizeof(shared_secret), &key_derive_key)) {
        return false;
    }

    // derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080)
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
            return false;
    }

    if (!compute_cmac_aes128(&key_derive_key, derive_msg, derive_msg_length, &derived_key)) {
        return false;
    }

    return true;
}

void bn2lebinpad(const BIGNUM *bn, unsigned char *to, size_t tolen)
{
    int len = BN_num_bytes(bn);
    BN_bn2bin(bn, to + tolen - len);
    if (len < tolen)
        memset(to, 0, tolen - len);
    reverse(to, to + tolen);  // Reverse to little-endian
}

bool ecdsa(const sgx_ec256_private_t &privkey, const uint8_t *data, uint32_t size, sgx_ec256_signature_t &signature) {
    bool result = true;

    vector<uint8_t> message(data, data + size);
    uint8_t digest[32];

    if (!calculate_sha256(message, (sgx_sha256_hash_t *)digest)) {
        return false;
    }

    // Convert sgx_ec256_private_t to BIGNUM (OpenSSL type)
    BIGNUM *bn_private = BN_lebin2bn(privkey.r, sizeof(privkey.r), NULL);

    if (bn_private == nullptr) {
        return false;
    }

    // Create a new EC_KEY object and set the private key
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == nullptr || EC_KEY_set_private_key(key, bn_private) != 1) {
        BN_free(bn_private);
        return false;
    }

    // Generate the ECDSA signature of the data
    ECDSA_SIG* sig = ECDSA_do_sign((unsigned char*)digest, SGX_SHA256_HASH_SIZE, key);
    char *r_hex, *s_hex;
    if (sig == nullptr) {
        result = false;
        goto cleanup;
    }

    // Now you need to convert the sig (ECDSA_SIG*) to sgx_ec256_signature_t.
    // Assuming that sgx_ec256_signature_t is a structure containing two 32-byte integers, you can do something like this:
    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    r_hex = BN_bn2hex(r);
    s_hex = BN_bn2hex(s);

    bn2lebinpad(r, (unsigned char *)signature.x, sizeof(signature.x));
    bn2lebinpad(s, (unsigned char *)signature.y, sizeof(signature.y));

cleanup:
    ECDSA_SIG_free(sig); // Clean up the signature
    EC_KEY_free(key); // Clean up the key
    BN_free(bn_private); // Clean up the BIGNUM
    return result;
}

bool compute_cmac_aes128(
    const sgx_cmac_128bit_key_t *p_key,
    const uint8_t *p_src,
    uint32_t src_len,
    sgx_cmac_128bit_tag_t *p_mac) {

    CMAC_CTX *ctx = CMAC_CTX_new();
    if (ctx == nullptr) {
        // handle error...
        return false;
    }

    if (!CMAC_Init(ctx, p_key, sizeof(*p_key), EVP_aes_128_cbc(), nullptr)) {
        // handle error...
        CMAC_CTX_free(ctx);
        return false;
    }

    if (!CMAC_Update(ctx, p_src, src_len)) {
        // handle error...
        CMAC_CTX_free(ctx);
        return false;
    }

    size_t cmac_length = sizeof(*p_mac);
    if (!CMAC_Final(ctx, (unsigned char*)p_mac, &cmac_length)) {
        // handle error...
        CMAC_CTX_free(ctx);
        return false;
    }

    CMAC_CTX_free(ctx);
    return true;
}

bool calculate_sha256(const std::vector<uint8_t>& message, sgx_sha256_hash_t *digest) {
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256))
        return false;
    if (!SHA256_Update(&sha256, message.data(), message.size()))
        return false;
    if (!SHA256_Final((unsigned char*)digest, &sha256))
        return false;
    return true;
}

bool sha256_digest(const unsigned char *msg, size_t mlen, unsigned char digest[32])
{
	EVP_MD_CTX *ctx;
    bool state = true;

	memset(digest, 0, 32);

	ctx= EVP_MD_CTX_new();
	if ( ctx == NULL ) {
		goto cleanup;
	}

	if ( EVP_DigestInit(ctx, EVP_sha256()) != 1 ) {
		goto cleanup;
	}

	if ( EVP_DigestUpdate(ctx, msg, mlen) != 1 ) {
		goto cleanup;
	}

	if ( EVP_DigestFinal(ctx, digest, NULL) != 1 ) {
		goto cleanup;
	}

cleanup:
	if ( ctx != NULL ) EVP_MD_CTX_destroy(ctx);
	return state;
}

int aes_gcm_decrypt(uint8_t *key, uint8_t *ciphertext, int ciphertext_len, uint8_t *plaintext, uint8_t *iv, int iv_len, uint8_t *aad,
    int aad_len, uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    /*if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();*/

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if((tag != NULL) && (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)))
        handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}

void handleErrors(){
    printf("There was a terrible error!\n");
}

int aes_gcm_encrypt(uint8_t *key, uint8_t *plaintext, int plaintext_len, uint8_t *ciphertext, uint8_t *iv, int iv_len, uint8_t *aad,
    int aad_len, uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
/*    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();*/

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if((tag != NULL) && (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}