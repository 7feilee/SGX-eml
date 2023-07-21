#ifndef SGX_EML_X509_UTILS_H
#define SGX_EML_X509_UTILS_H

#include <sgx_key_exchange.h>
#include "../httpparser/response.h"
#include "protocol.h"

sgx_status_t verify_certificate(const httpparser::Response &response, attestation_error_t &att_error);

#endif //SGX_EML_X509_UTILS_H
