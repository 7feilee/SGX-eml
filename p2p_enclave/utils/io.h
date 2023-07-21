#ifndef SGX_EML_IO_H
#define SGX_EML_IO_H

#include "tSgxSSL_api.h"
#include "p2p_enclave_t.h"

#define IO_BUFFER_SIZE 4096


int ocall_ssl_fprintf(Stream_t target, const char *fmt, va_list);
int ocall_fprintf(OutputTarget target, const char *fmt, ...);

#endif //SGX_EML_IO_H
