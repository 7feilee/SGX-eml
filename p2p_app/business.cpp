#include <string>
#include <vector>
#include <cstring>
#include "business.h"
#include <p2p_enclave_u.h>
#include <hexdump.h>
#include "sgx_utils/sgx_exception.hpp"

using namespace std;

void write_text_message(sgx_enclave_id_t enclave_id, CodecIO &codecIo, const string &message) {
    printf("[%4d] %s\n", __LINE__, "write_text_message ...");

    sgx_status_t status;

    vector<uint8_t> tuple_bytes(COUNTER_LENGTH_IN_BYTES + sizeof(uint32_t), 0);
    tuple_bytes.insert(tuple_bytes.end(), message.begin(), message.end());

    tuple_bytes.resize((tuple_bytes.size() / 32 + 1) * 32, 0);

    message_tuple &tuple = *(message_tuple *) &tuple_bytes[0];
    tuple.length = message.size();

    aes_ctr_128_encrypt(enclave_id, &status, (uint8_t *) &tuple.length,
                        tuple_bytes.size() - COUNTER_LENGTH_IN_BYTES, tuple.nonce);
    if (status != SGX_SUCCESS) {
        fprintf(stdout, "Error[%04x] @ %4d\n", status, __LINE__);
        exit(EXIT_FAILURE);
    }

    hexdump(stdout, tuple_bytes.data(), tuple_bytes.size());

    printf("[%4d] length is %lu\n", __LINE__, message.size());

    codecIo.write(tuple_bytes);
}

string read_text_message(sgx_enclave_id_t enclave_id, CodecIO &codecIo) {
    printf("[%4d] %s\n", __LINE__, "read_text_message ...");

    vector<uint8_t> tuple_bytes = codecIo.read();

    hexdump(stdout, tuple_bytes.data(), tuple_bytes.size());

    message_tuple &tuple = *(message_tuple *) &tuple_bytes[0];

    sgx_status_t status;
    aes_ctr_128_decrypt(enclave_id, &status, (uint8_t *) &tuple.length,
                        tuple_bytes.size() - COUNTER_LENGTH_IN_BYTES, tuple.nonce);

    if (status != SGX_SUCCESS) {
        fprintf(stdout, "Error[%04x] @ %4d\n", status, __LINE__);
        exit(EXIT_FAILURE);
    }

    printf("[%4d] length is %u\n", __LINE__, tuple.length);
    uint32_t length = tuple.length;

    return string(tuple.payload, tuple.payload + tuple.length);
}


char *Fgets(char *ptr, int n, FILE *stream) {
    char *rptr = fgets(ptr, n, stream);

    if (rptr == nullptr && ferror(stream)) {
        fprintf(stderr, "Fgets error");
    }
    return rptr;
}

void client_business(int conn_fd, sgx_enclave_id_t enclaveId) {
    printf("[%s: %4d] %s\n", "client", __LINE__, "started ...");
    CodecIO socket(conn_fd);

    string str = read_text_message(enclaveId, socket);

    puts("/**************** Receiving App Owner's secret ****************/\n");

    while (str.length() > 0) {
        printf("[%s: %4d] %s\n", "client", __LINE__, "Message coming");
        hexdump(stdout, (uint8_t *) str.c_str(), str.size());
        str = read_text_message(enclaveId, socket);
    }
}

void server_business(int conn_fd, sgx_enclave_id_t enclaveId) {
    sgx_status_t ret_status, sgx_status;
    char p_secret[16];
    char buf[MESSAGE_LENGTH];

    sgx_status = ecall_get_sp_secret(enclaveId, &ret_status, (uint8_t*)p_secret);

    if (sgx_status != SGX_SUCCESS) {
        throw sgx_error("ecall_get_sp_secret", sgx_status);
    }
    printf("[%s: %4d] %s\n", "server", __LINE__, "started ...");
    CodecIO socket(conn_fd);

    puts("/**************** Transferring(Unsealing and Encrypting) App Owner's secret ****************/\n");
    
    write_text_message(enclaveId, socket, p_secret);

    while (fgets(buf, MESSAGE_LENGTH, stdin)) {
        write_text_message(enclaveId, socket, buf);
    }
}
