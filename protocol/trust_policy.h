#ifndef SGX_EML_TRUST_POLICY_H
#define SGX_EML_TRUST_POLICY_H

#include <sgx_tkey_exchange.h>

typedef struct _ra_trust_policy {
    int allow_debug;
    int allow_configuration_needed;
    sgx_prod_id_t isv_product_id;
    sgx_isv_svn_t isv_min_svn;
    sgx_measurement_t mrsigner;
    sgx_measurement_t mrenclave;
} ra_trust_policy;

#endif //SGX_EML_TRUST_POLICY_H
