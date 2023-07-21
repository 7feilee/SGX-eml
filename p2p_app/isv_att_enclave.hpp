#ifndef SGX_EML_ISV_ATTESTATION_H
#define SGX_EML_ISV_ATTESTATION_H

#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <sgx_urts.h>
#include <exception>
#include <string>
#include <utility>
#include "config.h"
#include "p2p_enclave_u.h"
#include "sgx_utils/sgx_exception.hpp"

using namespace std;


class isv_att_enclave {
    sgx_enclave_id_t eid;
    bool client_use_platform_services;
    sgx_ra_context_t ra_ctx = 0xdeadbeef;

    uint32_t msg0 = 0;
    vector<uint8_t> msg1_bytes;
    vector<uint8_t> msg3_bytes;

    array<uint8_t, SGX_SHA256_HASH_SIZE> key_hash;

public:
    isv_att_enclave(sgx_enclave_id_t enclave_id, const UserArgs &user_args) :
            eid(enclave_id),
            client_use_platform_services(user_args.get_client_use_platform_services()) {
        /*
         * WARNING! Normally, the public key would be hardcoded into the
         * enclave, not passed in as a parameter. Hardcoding prevents
         * the enclave using an unauthorized key.
         *
         * This is diagnostic/test application, however, so we have
         * the flexibility of a dynamically assigned key.
         */

        sgx_status_t sgx_status, ret_status, pse_status;

//        if (debug) fprintf(stderr, "+++ using default public key\n");
        sgx_status = enclave_ra_init_def(eid, &ret_status, client_use_platform_services, &ra_ctx, &pse_status);

        /* Did the ECALL succeed? */
        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("enclave_ra_init", sgx_status);
        }

        /* If we asked for a PSE session, did that succeed? */
        if (client_use_platform_services) {
            if (pse_status != SGX_SUCCESS) {
                throw sgx_error("pse_session", pse_status);
            }
        }

        /* Did sgx_ra_init() succeed? */
        if (ret_status != SGX_SUCCESS) {
            throw sgx_error("sgx_ra_init", ret_status);
        }
    }

    ~isv_att_enclave() {
        sgx_status_t ret_status;
        enclave_ra_close(eid, &ret_status, ra_ctx);
    }

    const uint32_t &generate_msg0() {
        sgx_status_t sgx_status = sgx_get_extended_epid_group_id(&msg0);

        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("sgx_get_extended_epid_group_id", sgx_status);
        }

        return msg0;
    }

    const vector<uint8_t> &generate_msg1() {
        sgx_ra_msg1_t msg1;

        sgx_status_t sgx_status = sgx_ra_get_msg1(ra_ctx, eid, sgx_ra_get_ga, &msg1);

        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("sgx_ra_get_msg1", sgx_status);
        }

        msg1_bytes.assign((uint8_t *) &msg1, (uint8_t *) &msg1 + sizeof(msg1));
        return msg1_bytes;
    }

    const vector<uint8_t> &generate_msg3(const vector<uint8_t> &msg2_bytes) {
        const auto *msg2 = (const sgx_ra_msg2_t *) msg2_bytes.data();
        sgx_ra_msg3_t *msg3 = nullptr;
        uint32_t msg3_sz = 0;

        sgx_status_t sgx_status = sgx_ra_proc_msg2(
                ra_ctx, eid, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
                msg2, msg2_bytes.size(), &msg3, &msg3_sz
        );
        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("sgx_ra_proc_msg2", sgx_status);
        }

        msg3_bytes.assign((uint8_t *) msg3, (uint8_t *) msg3 + msg3_sz);
        return msg3_bytes;
    }

    const void save_secret(const uint8_t *p_secret, const uint8_t *p_gcm_mac){
        sgx_status_t sgx_status, ret_status;
        sgx_status = ecall_isv_put_secret(
                eid, &ret_status, ra_ctx,
                p_secret, p_gcm_mac);

        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("ecall_isv_put_secret", sgx_status);
        }
    }

    const array<uint8_t, 32> &generate_key() {
        sgx_status_t ret_status, sgx_status;
        sgx_sha256_hash_t *hash = (sgx_sha256_hash_t *) &key_hash[0];
        sgx_status = ecall_isv_init_share_key(eid, &ret_status, ra_ctx, hash);

        if (sgx_status != SGX_SUCCESS) {
            throw sgx_error("ecall_isv_init_share_key", sgx_status);
        }

        return key_hash;
    }
};


#endif //SGX_EML_ISV_ATTESTATION_H
