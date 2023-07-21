#ifndef SGX_EML_SP_ATTESTATION_H
#define SGX_EML_SP_ATTESTATION_H

#include "ias_request/httpparser/httpresponseparser.h"
#include "ias_request/httpparser/response.h"

#include "sgx_utils/sgx_exception.hpp"
#include "utils/crypto_utils.h"
#include "trust_policy.h"
#include "utils/cert_utils.h"
#include "utils/base64.h"
#include <json.hpp>

class sp_att {

    const sgx_ec256_private_t service_private_key = {
            {
                0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
                0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
                0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
                0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
            }
    };

    const unsigned char msg[16] = {
        'd', 'e', 'a', 'd', 'b', 'e', 'e', 'f',
        'd', 'e', 'a', 'd', 'b', 'e', 'e', 'f'
    };

    typedef struct ra_secret_struct {
        sgx_ec256_private_t private_b;
        sgx_ec256_public_t public_b;
        sgx_ec256_public_t public_a;    // msg1
        sgx_epid_group_id_t client_gid; // msg1
        sgx_ec256_dh_shared_t shared_secret;
        sgx_cmac_128bit_key_t smk;
        sgx_cmac_128bit_key_t sk;
    } ra_secret_t;

    ra_secret_t secret;

    ra_trust_policy policy{};
    sgx_spid_t spid;
    sgx_quote_sign_type_t quote_type;
    bool flag_verbose = false;

    vector<uint8_t> msg2_bytes;
    vector<uint8_t> msg4_bytes;
    

public:
    sp_att(const UserArgs &user_args) {
        policy.allow_debug = user_args.get_policy_allow_debug();
        flag_verbose = user_args.get_sgx_verbose();
        policy.allow_configuration_needed = user_args.get_policy_allow_configuration_needed();
        policy.isv_product_id = user_args.get_policy_product_id();
        policy.isv_min_svn = user_args.get_policy_isv_min_svn();
        memcpy(&policy.mrsigner, user_args.get_policy_mrsigner().data(), sizeof(sgx_measurement_t));

        spid = user_args.get_spid();
        quote_type = user_args.get_quote_type();

		/* Initialize out support libraries */

		crypto_init();

    }

    ~sp_att() {
        crypto_destroy();
    }

    const vector<uint8_t> &process_msg01(const vector<uint8_t> &msg01_bytes, const string &sigrl) {
        sgx_status_t sgx_status;
        attestation_error_t att_error;
        ra_msg01_t &msg01 = *(ra_msg01_t *) msg01_bytes.data();

        msg2_bytes.resize(sizeof(sgx_ra_msg2_t) + sigrl.size(), 0);
        
        if(flag_verbose){
            printf("msg0_extended_epid_group_id=%08x \n",msg01.msg0_extended_epid_group_id);
            fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
        }

        if (msg01.msg0_extended_epid_group_id != 0) {
            att_error = MSG0_ExtendedEpidGroupIdIsNotZero;
             throw sgx_error("call_sp_proc_msg01 <att: " + to_string(att_error) + ">", SGX_ERROR_UNEXPECTED);
        }

        /* Verify A's EC key */
        sgx_ra_msg1_t &msg1 = msg01.msg1;
        bool valid;



        valid = key_verify(msg1.g_a);
        if (!valid) {
            att_error = MSG1_ClientEnclaveSessionKeyIsInvalid;
            fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
            throw sgx_error("call_sp_proc_msg01 <att: " + to_string(att_error) + ">", SGX_ERROR_UNEXPECTED);
        }
        memcpy(&secret.public_a, &msg1, sizeof(sgx_ra_msg1_t));

        if(!key_generate(secret.private_b, secret.public_b)){
            fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
            throw sgx_error("call_sp_proc_msg01 <att: Failed to generate key pair>", SGX_ERROR_UNEXPECTED);
        }

        if(!ecdh_shared_secret(secret.private_b, secret.public_a, secret.shared_secret))
            throw sgx_error("call_sp_proc_msg01 <att: Failed to do ECDH key exchange>", SGX_ERROR_UNEXPECTED);


        // fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);

        if(!derive_key(DERIVE_KEY_SMK, secret.shared_secret, secret.smk))
            throw sgx_error("call_sp_proc_msg01 <att: Failed to derive SMK>", SGX_ERROR_UNEXPECTED);
            
        sgx_ra_msg2_t &msg2 = *(sgx_ra_msg2_t *) msg2_bytes.data();
        memcpy(&msg2.g_b, &secret.public_b, sizeof(sgx_ec256_public_t));

        /* SPID */
        memcpy(&msg2.spid, &spid, sizeof(sgx_spid_t));

        /* Quote Type */
        msg2.quote_type = (quote_type == SGX_UNLINKABLE_SIGNATURE) ? 0 : 1;

        /* KDF-ID */
        msg2.kdf_id = 1;

        /* SigSP */
        array<sgx_ec256_public_t, 2> Gb_Ga{secret.public_b, secret.public_a};
        if(!ecdsa(service_private_key, (uint8_t *) &Gb_Ga[0], 2 * sizeof(sgx_ec256_public_t), msg2.sign_gb_ga))
            throw sgx_error("call_sp_proc_msg01 <att: Failed to sign message>", SGX_ERROR_UNEXPECTED);

        /* CMACsmk */
        if(!compute_cmac_aes128(&secret.smk, (uint8_t *) &msg2, 148, &msg2.mac))
            throw sgx_error("call_sp_proc_msg01 <att: Failed to CMAC message>", SGX_ERROR_UNEXPECTED);

        /* SigRL */
        uint32_t sigrl_size = sigrl.size(); 
        msg2.sig_rl_size = sigrl_size;
        memcpy(msg2.sig_rl, sigrl.c_str(), sigrl_size);

        return msg2_bytes;
    }

    const vector<uint8_t> &process_msg3(const vector<uint8_t> &msg3_bytes, const string &attestation_report) {
        sgx_status_t sgx_status, ret_status;
        attestation_error_t att_error;

        msg4_bytes.resize(sizeof(ra_msg4_t), 0);
        sgx_ra_msg3_t& msg3 = *(sgx_ra_msg3_t *) msg3_bytes.data();
        const sgx_quote_t &quote = *(sgx_quote_t *) msg3.quote;

        /* Verify that Ga in msg3 matches Ga in msg1 */
        if (memcmp(&secret.public_a, &msg3.g_a, sizeof(sgx_ec256_public_t)) != 0) {
            att_error = MSG3_ClientEnclaveSessingKeyMismatch;
            throw sgx_error("call_sp_proc_msg3 <att: " + to_string(att_error) + ">", SGX_ERROR_UNEXPECTED);
        }

        /* Verify that the EPID group ID in the quote matches the one from msg1 */
        if (memcmp(secret.client_gid, quote.epid_group_id, sizeof(sgx_epid_group_id_t)) != 0) {
            att_error = MSG3_EpidGroupIdMismatch;
            throw sgx_error("call_sp_proc_msg3 <att: " + to_string(att_error) + ">", SGX_ERROR_UNEXPECTED);
        }

        /* Verify CMACsmk of M */
        uint32_t quote_size = 436 + quote.signature_len;
        uint32_t M_length = sizeof(sgx_ra_msg3_t) - sizeof(sgx_mac_t) + quote_size;

        sgx_cmac_128bit_tag_t mac;
        if(!compute_cmac_aes128(&secret.smk, (uint8_t *) &msg3.g_a, M_length, &mac))
            throw sgx_error("call_sp_proc_msg3 <att: Failed to CMAC message>", SGX_ERROR_UNEXPECTED);


        if (memcmp(msg3.mac, mac, SGX_CMAC_MAC_SIZE) != 0) {
            throw sgx_error("call_sp_proc_msg3 <att: " + to_string(SGX_ERROR_MAC_MISMATCH) + ">", SGX_ERROR_UNEXPECTED);
        }

        /* Verify that the first 64 bytes of the report data (inside the quote) are SHA256(Ga||Gb||VK)||0x00[32] */
        /* Derive VK */
        sgx_cmac_128bit_key_t vk;
        if(!derive_key(DERIVE_KEY_VK, secret.shared_secret, vk))
            throw sgx_error("call_sp_proc_msg3 <att: Fail to derive VK>", SGX_ERROR_UNEXPECTED);

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
        if(!calculate_sha256(plaintext, &digest))
            throw sgx_error("call_sp_proc_msg3 <att: Fail to calc SHA-256 digest of (Ga || Gb || VK)>", SGX_ERROR_UNEXPECTED);

        /* verify */
        vector<uint8_t> verification(begin(digest), end(digest));
        verification.resize(SGX_REPORT_DATA_SIZE, 0);

        const uint8_t *report_data = quote.report_body.report_data.d;
        if (memcmp(verification.data(), report_data, SGX_REPORT_DATA_SIZE) != 0) {
            att_error = MSG3_InvalidReportData;
            throw sgx_error("call_sp_proc_msg3 <att: " + to_string(att_error) + ">", SGX_ERROR_UNEXPECTED);
        }

        const string attestation_response = attestation_report.c_str();

        /* parse attestation_report */
        // printf("%s [%4d] %s : %s\n", __FILE__, __LINE__, __FUNCTION__,  attestation_response.c_str());
        httpparser::Response response;
        httpparser::HttpResponseParser parser;
        httpparser::HttpResponseParser::ParseResult result = parser.parse(response, attestation_response);
        if (result != httpparser::HttpResponseParser::ParsingCompleted) {
            att_error = ATTR_ParseFailed;
            throw sgx_error("call_sp_proc_msg3 <att: " + to_string(att_error) + ">", SGX_ERROR_UNEXPECTED);
        }

        /* verify signature */
        // printf("%s [%4d] %s : %s\n", __FILE__, __LINE__, __FUNCTION__,  "verify signature");
        if(SGX_SUCCESS != verify_certificate(response, att_error))
            throw sgx_error("call_sp_proc_msg3 <att: " + to_string(att_error) + ">", SGX_ERROR_UNEXPECTED);

        /* process attestation_report */
        // printf("%s [%4d] %s : %s\n",  __FILE__, __LINE__, __FUNCTION__,  "process attestation_report");
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

        ra_msg4_t &msg4 = *(ra_msg4_t *) msg4_bytes.data();
        memset(&msg4, 0, sizeof(ra_msg4_t));

        puts("/**************** Getting Remote Attestation Result ... ****************/\n");

        string isvEnclaveQuoteStatus = reportObj["isvEnclaveQuoteStatus"].ToString();
        if (isvEnclaveQuoteStatus == "OK" || isvEnclaveQuoteStatus == "GROUP_OUT_OF_DATE") {

            puts("\033[31m/**************** Trusted ****************/\n\033[0m");

            msg4.status = Trusted;
            puts("/**************** Ephemeral elliptic curve Diffie-Hellman key deriving DERIVE_KEY_SK ...  ****************/\n");
            if(!derive_key(DERIVE_KEY_SK, secret.shared_secret, secret.sk))
                throw sgx_error("call_sp_proc_msg01 <att: Failed to derive SK>", SGX_ERROR_UNEXPECTED);
            uint8_t aes_gcm_iv[12] = {0};
            puts("/**************** Encrypting and Sending the secret ... ****************/\n");
            aes_gcm_encrypt(secret.sk, (uint8_t*)msg, 16, msg4.secret.payload, &aes_gcm_iv[0], 12, NULL, 0, msg4.secret.payload_tag);
        } else if (isvEnclaveQuoteStatus == "CONFIGURATION_NEEDED") {
            msg4.status = policy.allow_configuration_needed ? Trusted_Complicated : NotTrusted_Complicated;
        } else if (isvEnclaveQuoteStatus == "GROUP_OUT_OF_DATE") {
            msg4.status = NotTrusted_Complicated;
        } else {
            msg4.status = NotTrusted;
        }

        if (msg4.status == Trusted || msg4.status == NotTrusted_Complicated) {
            string isvEnclaveQuoteBody = reportObj["isvEnclaveQuoteBody"].ToString();
            vector<uint8_t> quote_bytes = base64_decode(isvEnclaveQuoteBody);
            const sgx_quote_t &quote = *(sgx_quote_t *) quote_bytes.data();
            const sgx_report_body_t &report_body = quote.report_body;

            if (!policy.allow_debug && report_body.attributes.flags & SGX_FLAGS_DEBUG) {
                // Is the enclave compiled in debug mode?
                msg4.status = NotTrusted;
                printf("%s [%4d] %s : %s\n", __FILE__, __LINE__, __FUNCTION__,  "allow_debug");
            } else if (report_body.isv_prod_id != policy.isv_product_id) {
                // Does the ISV product ID meet the minimum requirement?
                msg4.status = NotTrusted;
                printf("%s [%4d] %s : %s\n", __FILE__, __LINE__, __FUNCTION__,  "isv_prod_id");
            } else if (report_body.isv_svn < policy.isv_min_svn) {
                // Does the ISV SVN meet the minimum version?
                msg4.status = NotTrusted;
                printf("%s [%4d] %s : %s\n", __FILE__, __LINE__, __FUNCTION__,  "isv_svn");
            } else if (memcmp(&report_body.mr_signer, &policy.mrsigner, sizeof(sgx_measurement_t)) != 0) {
                // Does the MRSIGNER match?
                
                msg4.status = NotTrusted;
                printf("%s [%4d] %s : %s\n", __FILE__, __LINE__, __FUNCTION__,  "isv_mrsigner");
            }
            sgx_measurement_t mrenclave = report_body.mr_enclave;
            
            for (int i = 0; i < 32; ++i) {
                printf("%02x", mrenclave.m[i]);
            }
            printf("\n");
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

        return msg4_bytes;
    }

};

#endif //SGX_EML_SP_ATTESTATION_H
