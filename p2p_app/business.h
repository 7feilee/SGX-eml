#ifndef SGX_EML_BUSINESS_H
#define SGX_EML_BUSINESS_H


#include <codec_io.hpp>
#include <sgx_eid.h>

#define MESSAGE_LENGTH 256

#ifndef COUNTER_LENGTH_IN_BYTES
#define COUNTER_LENGTH_IN_BYTES 16
#endif

struct message_tuple {
    uint8_t nonce[COUNTER_LENGTH_IN_BYTES];
    uint32_t length;
    uint8_t payload[];
};

void client_business(int conn_fd, sgx_enclave_id_t enclaveId);

void server_business(int conn_fd, sgx_enclave_id_t enclaveId);


#endif //SGX_EML_BUSINESS_H
