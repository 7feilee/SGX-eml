#include <sgx_tkey_exchange.h>
#include "protocol.h"
#include "sp_routines.h"
#include "p2p_enclave_t.h"
#include "utils/crypto_utils.h"
#include <tlibc/mbusafecrt.h>
#include <string>

using namespace std;

static const sgx_ec256_private_t service_private_key = {
        {
                0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
                0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
                0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
                0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
        }
};

ra_secret_t secret;

sgx_status_t ecall_sp_proc_msg01(sgx_spid_t spid, sgx_quote_sign_type_t quote_type,
                                 ra_msg01_t msg01, const char *sigrl, uint32_t sigrl_size,
                                 sgx_ra_msg2_t *msg2, uint32_t msg2_size, attestation_error_t *att_error) {
    if (!msg2 || !att_error) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (msg2_size != sizeof(sgx_ra_msg2_t) + sigrl_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t status;
    *att_error = NoErrorInformation;

    /* proc msg0 */
    status = private_proc_msg0(msg01.msg0_extended_epid_group_id, *att_error);
    check_sgx_status(status);

    /* proc msg1 */
    status = private_proc_msg1(secret, msg01.msg1, *att_error);
    check_sgx_status(status);

    /* build msg2 */
    status = private_build_msg2(secret, service_private_key, spid, quote_type, sigrl, sigrl_size, *msg2);
    check_sgx_status(status);

    return status;
}


sgx_status_t ecall_sp_proc_msg3(const sgx_ra_msg3_t *msg3, uint32_t msg3_size, const char *attestation_report,
                                ra_trust_policy policy, ra_msg4_t *msg4, attestation_error_t *att_error) {

    if (!attestation_report || !att_error || !msg3 || !msg4) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    auto *quote = (sgx_quote_t *) msg3->quote;
    if (msg3_size != sizeof(sgx_ra_msg3_t) + sizeof(sgx_quote_t) + quote->signature_len) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t status;
    *att_error = NoErrorInformation;

    /* proc msg3 */
    status = private_proc_msg3(secret, *msg3, *att_error);
    check_sgx_status(status);

    /* build msg4 */
    const string attestation_response = attestation_report;
    status = private_build_msg4(secret, attestation_response, policy, *msg4, *att_error);
    check_sgx_status(status);

    return status;
}

