#ifndef SGX_EML_BUSINESS_H
#define SGX_EML_BUSINESS_H

#include <codec_io.hpp>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


#define MESSAGE_LENGTH 256

void client_business(int conn_fd, RSA &publicKey);

void server_business(int conn_fd, RSA &privateKey);

#endif //SGX_EML_BUSINESS_H
