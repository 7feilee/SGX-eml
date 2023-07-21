#ifndef SGX_EML_SP_ROUTINES_H
#define SGX_EML_SP_ROUTINES_H

#include <vector>
#include <sgx_key_exchange.h>
#include "protocol.h"
#include "trust_policy.h"

using namespace std;

typedef struct ra_secret_struct {
    sgx_ec256_private_t private_b;
    sgx_ec256_public_t public_b;
    sgx_ec256_public_t public_a;    // msg1
    sgx_epid_group_id_t client_gid; // msg1
    sgx_ec256_dh_shared_t shared_secret;
    sgx_cmac_128bit_key_t smk;
    sgx_cmac_128bit_key_t sk;
} ra_secret_t;

#define check_sgx_status(status) if(status != SGX_SUCCESS) return status;

sgx_status_t private_proc_msg0(uint32_t msg0_extended_epid_group_id,
                               attestation_error_t &att_error);

sgx_status_t private_proc_msg1(ra_secret_t &secret,
                               const sgx_ra_msg1_t &msg1,
                               attestation_error_t &att_error);

sgx_status_t private_build_msg2(ra_secret_t &secret,
                                const sgx_ec256_private_t &service_provider_privkey,
                                const sgx_spid_t &spid,
                                const sgx_quote_sign_type_t &quote_type,
                                const char *sigrl,
                                uint32_t sigrl_size,
                                sgx_ra_msg2_t &msg2);

sgx_status_t private_proc_msg3(ra_secret_t &secret,
                               const sgx_ra_msg3_t &msg3,
                               attestation_error_t &att_error);

sgx_status_t private_build_msg4(ra_secret_t &secret,
                                const string &attestation_response,
                                const ra_trust_policy &policy,
                                ra_msg4_t &msg4,
                                attestation_error_t &att_error);

#endif //SGX_EML_SP_ROUTINES_H
