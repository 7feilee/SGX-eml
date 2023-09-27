#include "httpparser/httpresponseparser.h"
#include "httpparser/response.h"

#include "sp_routines.h"
#include "utils/crypto_utils.h"
#include <array>
#include "p2p_enclave_t.h"
#include <mbusafecrt.h>
#include "utils/cert_utils.h"
#include "utils/json.hpp"
#include "utils/base64.h"

using namespace std;

void print_256_msg(const char *header, const uint32_t *data) {
    char buffer[256];

    sprintf_s(buffer, 256, "%s = %08x %08x %08x %08x %08x %08x %08x %08x", header,
              data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);

    ocall_eputs(__FILE__, __FUNCTION__, __LINE__, buffer);
}


sgx_status_t private_proc_msg0(uint32_t msg0_extended_epid_group_id, attestation_error_t &att_error) {
#ifdef VERBOSE
    char buffer[256];
    sprintf_s(buffer, 256, "msg0_extended_epid_group_id=%08x", msg0_extended_epid_group_id);
    ocall_eputs(__FILE__, __FUNCTION__, __LINE__, buffer);
#endif

    if (msg0_extended_epid_group_id == 0) {
        return SGX_SUCCESS;
    } else {
        att_error = MSG0_ExtendedEpidGroupIdIsNotZero;
        return SGX_ERROR_UNEXPECTED;
    }
}


sgx_status_t private_proc_msg1(ra_secret_t &secret, const sgx_ra_msg1_t &msg1, attestation_error_t &att_error) {
    /* All components of msg1 are in little-endian byte order. */

    sgx_status_t status;

    /* Verify A's EC key */
    bool valid;
    status = key_verify(msg1.g_a, valid);

    check_sgx_status(status);
    if (!valid) {
        att_error = MSG1_ClientEnclaveSessionKeyIsInvalid;
        return SGX_ERROR_UNEXPECTED;
    }

    memcpy(&secret.public_a, &msg1, sizeof(sgx_ra_msg1_t));

    /* Generate a random EC key using the P-256 curve. This key will become Gb. */
    status = key_generate(secret.private_b, secret.public_b);
    check_sgx_status(status);

    /* Derive the key derivation key (KDK) from Ga and Gb: */
    status = ecdh_shared_secret(secret.private_b, secret.public_a, secret.shared_secret);
    check_sgx_status(status);

    /* Derive SMK */
    status = derive_key(DERIVE_KEY_SMK, secret.shared_secret, secret.smk);
    check_sgx_status(status);

    return status;
}

sgx_status_t private_build_msg2(ra_secret_t &secret, const sgx_ec256_private_t &service_provider_privkey,
                                const sgx_spid_t &spid, const sgx_quote_sign_type_t &quote_type,
                                const char *sigrl, uint32_t sigrl_size, sgx_ra_msg2_t &msg2) {
    sgx_status_t status;

    /* Gb */
    memcpy(&msg2.g_b, &secret.public_b, sizeof(sgx_ec256_public_t));

    /* SPID */
    memcpy(&msg2.spid, &spid, sizeof(sgx_spid_t));

    /* Quote Type */
    msg2.quote_type = (quote_type == SGX_UNLINKABLE_SIGNATURE) ? 0 : 1;

    /* KDF-ID */
    msg2.kdf_id = 1;

    /* SigSP */
    array<sgx_ec256_public_t, 2> Gb_Ga{secret.public_b, secret.public_a};
    status = ecdsa(service_provider_privkey, (uint8_t *) &Gb_Ga[0], 2 * sizeof(sgx_ec256_public_t), msg2.sign_gb_ga);
    check_sgx_status(status);

    /* CMACsmk */
    status = sgx_rijndael128_cmac_msg(&secret.smk, (uint8_t *) &msg2, 148, &msg2.mac);
    check_sgx_status(status);

    /* SigRL */
    msg2.sig_rl_size = sigrl_size;
    memcpy_s(msg2.sig_rl, sigrl_size, sigrl, sigrl_size);

    return status;
}

sgx_status_t private_proc_msg3(ra_secret_t &secret, const sgx_ra_msg3_t &msg3, attestation_error_t &att_error) {
    sgx_status_t status;
    const sgx_quote_t &quote = *(sgx_quote_t *) msg3.quote;

    /* Verify that Ga in msg3 matches Ga in msg1 */
    if (memcmp(&secret.public_a, &msg3.g_a, sizeof(sgx_ec256_public_t)) != 0) {
        att_error = MSG3_ClientEnclaveSessingKeyMismatch;
        return SGX_ERROR_UNEXPECTED;
    }

    /* Verify that the EPID group ID in the quote matches the one from msg1 */
    if (memcmp(secret.client_gid, quote.epid_group_id, sizeof(sgx_epid_group_id_t)) != 0) {
        att_error = MSG3_EpidGroupIdMismatch;
        return SGX_ERROR_UNEXPECTED;
    }

    /* Verify CMACsmk of M */
    uint32_t quote_size = 436 + quote.signature_len;
    uint32_t M_length = sizeof(sgx_ra_msg3_t) - sizeof(sgx_mac_t) + quote_size;

    sgx_cmac_128bit_tag_t mac;
    status = sgx_rijndael128_cmac_msg(&secret.smk, (uint8_t *) &msg3.g_a, M_length, &mac);
    check_sgx_status(status);

    if (memcmp(msg3.mac, mac, SGX_CMAC_MAC_SIZE) != 0) {
        return SGX_ERROR_MAC_MISMATCH;
    }

    /* Verify that the first 64 bytes of the report data (inside the quote) are SHA256(Ga||Gb||VK)||0x00[32] */
    /* Derive VK */
    sgx_cmac_128bit_key_t vk;
    status = derive_key(DERIVE_KEY_VK, secret.shared_secret, vk);
    check_sgx_status(status);

    /* Build our plaintext */
    vector<uint8_t> plaintext;
    plaintext.reserve(sizeof(sgx_ec256_public_t) * 2 + sizeof(sgx_cmac_128bit_key_t));

    auto *ptr = (uint8_t *) &secret.public_a;
    plaintext.insert(plaintext.end(), ptr, ptr + sizeof(sgx_ec256_public_t));
    ptr = (uint8_t *) &secret.public_b;
    plaintext.insert(plaintext.end(), ptr, ptr + sizeof(sgx_ec256_public_t));
    ptr = (uint8_t *) &vk;
    plaintext.insert(plaintext.end(), ptr, ptr + sizeof(sgx_cmac_128bit_key_t));

    /* Calculate SHA-256 digest of (Ga || Gb || VK) */
    sgx_sha256_hash_t digest;
    status = sgx_sha256_msg(plaintext.data(), plaintext.size(), &digest);
    check_sgx_status(status);

    /* verify */
    vector<uint8_t> verification(begin(digest), end(digest));
    verification.resize(SGX_REPORT_DATA_SIZE, 0);

    const uint8_t *report_data = quote.report_body.report_data.d;
    if (memcmp(verification.data(), report_data, SGX_REPORT_DATA_SIZE) != 0) {
        att_error = MSG3_InvalidReportData;
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

sgx_status_t private_build_msg4(ra_secret_t &secret, const string &attestation_response, const ra_trust_policy &policy,
                                ra_msg4_t &msg4, attestation_error_t &att_error) {
    sgx_status_t status = SGX_SUCCESS;

    /* parse attestation_report */
    // ocall_eputs(__FILE__, __FUNCTION__, __LINE__, attestation_response.c_str());
    httpparser::Response response;
    httpparser::HttpResponseParser parser;
    httpparser::HttpResponseParser::ParseResult result = parser.parse(response, attestation_response);
    if (result != httpparser::HttpResponseParser::ParsingCompleted) {
        att_error = ATTR_ParseFailed;
        return SGX_ERROR_UNEXPECTED;
    }

    /* verify signature */
    // ocall_eputs(__FILE__, __FUNCTION__, __LINE__, "verify signature");
    status = verify_certificate(response, att_error);
    check_sgx_status(status);

    /* process attestation_report */
    // ocall_eputs(__FILE__, __FUNCTION__, __LINE__, "process attestation_report");
    json::JSON reportObj = json::JSON::Load(response.content_string());


    /*
   * This sample's attestion policy is based on isvEnclaveQuoteStatus:
   *
   *   1) if "OK" or "GROUP_OUT_OF_DATE" then return "Trusted"
   *
   *   2) if "CONFIGURATION_NEEDED" then return "NotTrusted_ItsComplicated" when in --strict-trust-mode
   *        and "Trusted_ItsComplicated" otherwise
   *
   *   3) return "NotTrusted" for all other responses
   *
   * Complicated means the client is not trusted, but can conceivable take action that will allow it to be trusted
   * (such as a BIOS update).
    */

    // TODO: return this for further check
    unsigned int report_version = (unsigned int) reportObj["version"].ToInt();

    memset(&msg4, 0, sizeof(ra_msg4_t));

    string isvEnclaveQuoteStatus = reportObj["isvEnclaveQuoteStatus"].ToString();
    if (isvEnclaveQuoteStatus == "OK") {
        msg4.status = Trusted;
    } else if (isvEnclaveQuoteStatus == "CONFIGURATION_NEEDED") {
        msg4.status = policy.allow_configuration_needed ? Trusted_Complicated : NotTrusted_Complicated;
    } else if (isvEnclaveQuoteStatus == "GROUP_OUT_OF_DATE") {
        msg4.status = NotTrusted_Complicated;
    } else {
        msg4.status = NotTrusted;
    }

    uint8_t src[256 + 32 + 32];

    if (msg4.status == Trusted || msg4.status == NotTrusted_Complicated) {
        string isvEnclaveQuoteBody = reportObj["isvEnclaveQuoteBody"].ToString();
        vector<uint8_t> quote_bytes = base64_decode(isvEnclaveQuoteBody);
        const sgx_quote_t &quote = *(sgx_quote_t *) quote_bytes.data();
        const sgx_report_body_t &report_body = quote.report_body;
        int rv = 0;
        ocall_fputs(&rv, TO_STDOUT, "/**************** Unsealing App Owner's sk, App Enclave's MRSIGNER, MRENCLAVE ****************/\n");
        char filename_buf[FILENAME_BUF_LEN];
        memcpy(src + 256, &report_body.mr_signer, 32);
        memcpy(src + 256 + 32, &report_body.mr_enclave, 32);
        status = get_filename(&src[256], filename_buf);
        check_sgx_status(status);

        SGX_FILE* fp = sgx_fopen_auto_key(filename_buf, "rb");
        if (fp == NULL) {
            return SGX_ERROR_UNEXPECTED;
        }
        // Assuming the file contains exactly SAMPLE_PAYLOAD_SIZE bytes.
        size_t readsize = sgx_fread(src, 1, SAMPLE_PAYLOAD_SIZE, fp);

        sgx_fclose(fp);

        if (readsize != SAMPLE_PAYLOAD_SIZE) {
            return SGX_ERROR_UNEXPECTED;
        }

        if (!policy.allow_debug && report_body.attributes.flags & SGX_FLAGS_DEBUG) {
            // Is the enclave compiled in debug mode?
            msg4.status = NotTrusted;
            ocall_eputs(__FILE__, __FUNCTION__, __LINE__, "allow_debug");
        } else if (report_body.isv_prod_id != policy.isv_product_id) {
            // Does the ISV product ID meet the minimum requirement?
            msg4.status = NotTrusted;
            ocall_eputs(__FILE__, __FUNCTION__, __LINE__, "isv_prod_id");
        } else if (report_body.isv_svn < policy.isv_min_svn) {
            // Does the ISV SVN meet the minimum version?
            msg4.status = NotTrusted;
            ocall_eputs(__FILE__, __FUNCTION__, __LINE__, "isv_svn");
        } else if (memcmp(&report_body.mr_signer, &src[256], sizeof(sgx_measurement_t)) != 0) {
            // Does the MRSIGNER match?
           msg4.status = NotTrusted;
           ocall_eputs(__FILE__, __FUNCTION__, __LINE__, "isv_mr_signer");
        } else if (memcmp(&report_body.mr_enclave, &src[256 + 32], sizeof(sgx_measurement_t)) != 0) {
            // Does the MRENCLAVE match?
           msg4.status = NotTrusted;
           ocall_eputs(__FILE__, __FUNCTION__, __LINE__, "isv_mr_enclave");
        }
    }

    if(msg4.status != NotTrusted){
        int rv = 0;

        status = derive_key(DERIVE_KEY_SK, secret.shared_secret, secret.sk);
        check_sgx_status(status);
        uint8_t aes_gcm_iv[12] = {0};
        status = sgx_rijndael128GCM_encrypt(reinterpret_cast<sgx_ec_key_128bit_t*>(&secret.sk), 
                                            (uint8_t*)src,
                                            SAMPLE_PAYLOAD_SIZE - 32 - 32,           
                                            msg4.secret.payload,
                                            &aes_gcm_iv[0],
                                            12,
                                            NULL,
                                            0,
                                            (sgx_aes_gcm_128bit_tag_t *)(&msg4.secret.payload_tag));
        check_sgx_status(status);
    }

#if 0
    /* Check to see if a platformInfoBlob was sent back as part of the response */
    if (!reportObj["platformInfoBlob"].IsNull()) {
        /* The platformInfoBlob has two parts, a TVL Header (4 bytes), and TLV Payload (variable) */
        string pibBuff = reportObj["platformInfoBlob"].ToString();

        /* remove the TLV Header (8 base16 chars, ie. 4 bytes) from the PIB Buff. */
        pibBuff.erase(pibBuff.begin(), pibBuff.begin() + (4 * 2));

//        int ret = from_hexstring((unsigned char *) &msg4->platformInfoBlob, pibBuff.c_str(), pibBuff.length() / 2);
    } else {
//        if (verbose) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
    }
#endif

    return SGX_SUCCESS;
}

