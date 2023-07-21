#ifndef SGX_EML_SP_ATTESTATION_H
#define SGX_EML_SP_ATTESTATION_H

#include "sgx_utils/sgx_exception.hpp"
#include "p2p_enclave_u.h"

class sp_att_enclave {
    sgx_enclave_id_t eid;
//    sgx_ra_context_t ra_ctx;

    ra_trust_policy policy{};
    sgx_spid_t spid;
    sgx_quote_sign_type_t quote_type;

    vector<uint8_t> msg2_bytes;
    vector<uint8_t> msg4_bytes;

    array<uint8_t, SGX_SHA256_HASH_SIZE> key_hash;
    array<uint8_t, 16> sp_secret;

public:
    sp_att_enclave(sgx_enclave_id_t enclave_id, const UserArgs &user_args) : eid(enclave_id) {
        policy.allow_debug = user_args.get_policy_allow_debug();
        policy.allow_configuration_needed = user_args.get_policy_allow_configuration_needed();
        policy.isv_product_id = user_args.get_policy_product_id();
        policy.isv_min_svn = user_args.get_policy_isv_min_svn();
        memcpy(&policy.mrsigner, user_args.get_policy_mrsigner().data(), sizeof(sgx_measurement_t));

        spid = user_args.get_spid();
        quote_type = user_args.get_quote_type();
    }

    const vector<uint8_t> &process_msg01(const vector<uint8_t> &msg01_bytes, const string &sigrl) {
        sgx_status_t sgx_status, ret_status;
        attestation_error_t att_error;
        ra_msg01_t &msg01 = *(ra_msg01_t *) msg01_bytes.data();

        msg2_bytes.resize(sizeof(sgx_ra_msg2_t) + sigrl.size(), 0);
        sgx_status = ecall_sp_proc_msg01(
                eid, &ret_status, spid, quote_type,
                msg01, sigrl.c_str(), sigrl.size(),
                (sgx_ra_msg2_t *) &msg2_bytes[0], msg2_bytes.size(), &att_error);

        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("ecall_sp_proc_msg01", sgx_status);
        }

        if (att_error != NoErrorInformation) {
            throw sgx_error("ecall_sp_proc_msg01 <att: " + to_string(att_error) + ">", SGX_ERROR_UNEXPECTED);
        }

        if (ret_status != SGX_SUCCESS) {
            throw sgx_error("ecall_sp_proc_msg01", sgx_status);
        }

        return msg2_bytes;
    }

    const vector<uint8_t> &process_msg3(const vector<uint8_t> &msg3_bytes, const string &attestation_response) {
        sgx_status_t sgx_status, ret_status;
        attestation_error_t att_error;

        msg4_bytes.resize(sizeof(ra_msg4_t), 0);
        sgx_status = ecall_sp_proc_msg3(
                eid, &ret_status,
                (sgx_ra_msg3_t *) msg3_bytes.data(), msg3_bytes.size(), attestation_response.c_str(), policy,
                (ra_msg4_t *) &msg4_bytes[0], &att_error);

        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("ecall_sp_proc_msg3", sgx_status);
        }

        if (att_error != NoErrorInformation) {
            throw sgx_error("ecall_sp_proc_msg3 <att: " + to_string(att_error) + ">", SGX_ERROR_UNEXPECTED);
        }

        if (ret_status != SGX_SUCCESS) {
            throw sgx_error("ecall_sp_proc_msg3", ret_status);
        }

        return msg4_bytes;
    }


    const array<uint8_t, 32> &generate_key() {
        sgx_status_t ret_status, sgx_status;
        sgx_sha256_hash_t *hash = (sgx_sha256_hash_t *) &key_hash[0];
        sgx_status = ecall_sp_init_share_key(eid, &ret_status, hash);

        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("ecall_sp_init_share_key", sgx_status);
        }

        return key_hash;
    }

    const array<uint8_t, 16> &get_sp_secret() {
        sgx_status_t ret_status, sgx_status;
        sgx_status = ecall_get_sp_secret(eid, &ret_status, sp_secret.data());

        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("ecall_get_sp_secret", sgx_status);
        }

        return sp_secret;
    }

};

#endif //SGX_EML_SP_ATTESTATION_H
