#include <string>
#include <vector>
#include <cstring>
#include <iostream>
#include "business.h"
#include <hexdump.h>

using namespace std;

void write_text_message(CodecIO &codecIo, const vector<uint8_t> &message, RSA *publicKey) {
    // printf("[%4d] %s\n", __LINE__, "write_text_message ...");

    int rsa_size = RSA_size(publicKey);
    unsigned char encryptedData[rsa_size];

    // Check if the message is too long for RSA encryption
    if (message.size() > rsa_size - 11) {
        cerr << "Message is too long for RSA encryption" << endl;
        exit(EXIT_FAILURE);
    }

    // Encrypt the message using RSA public key
    int encryptedLength = RSA_public_encrypt(message.size(), message.data(), encryptedData, publicKey, RSA_PKCS1_PADDING);
    if (encryptedLength == -1) {
        std::cerr << "RSA encryption failed" << std::endl;
        exit(EXIT_FAILURE);
    }
    // Convert encryptedData to a vector<uint8_t>
    vector<uint8_t> encryptedMessage(encryptedData, encryptedData + encryptedLength);
    // Write the encrypted message using codecIo.write
    codecIo.write(encryptedMessage);
}


vector<uint8_t> read_text_message(CodecIO &codecIo, RSA *privateKey) {
    // printf("[%4d] %s\n", __LINE__, "read_text_message ...");

    vector<uint8_t> encryptedMessage = codecIo.read();

    // Decrypt the received message using RSA private key
    unsigned char decryptedData[encryptedMessage.size()];

	BIO* BioPrivate = BIO_new_file("private_key.pem", "w+");
	int Result = PEM_write_bio_RSAPrivateKey(BioPrivate, privateKey, nullptr, nullptr, 0, nullptr, nullptr);
	BIO_free_all(BioPrivate); 

    int decryptedLength = RSA_private_decrypt(encryptedMessage.size(), encryptedMessage.data(), decryptedData, privateKey, RSA_PKCS1_PADDING);

    if (decryptedLength < 0) {
        unsigned long errCode = ERR_get_error();
        fprintf(stderr, "RSA_private_decrypt error: %s\n", ERR_error_string(errCode, nullptr));
        // Handle the error as needed
    }

    // Convert the decrypted data to a vector<uint8_t>
    vector<uint8_t> decryptedMessage(decryptedData, decryptedData + decryptedLength);

    return decryptedMessage;
}



char *Fgets(char *ptr, int n, FILE *stream) {
    char *rptr = fgets(ptr, n, stream);

    if (rptr == nullptr && ferror(stream)) {
        fprintf(stderr, "Fgets error");
    }
    return rptr;
}

void server_business(int conn_fd, RSA &privateKey) {
    printf("Waiting for encrypted message ... \n");
    CodecIO socket(conn_fd);

    vector<uint8_t> str_bytes = read_text_message(socket, &privateKey);

    while (str_bytes.size() > 0) {
        // printf("[%s: %4d] %s\n", "server", __LINE__, "Message coming");
        hexdump(stdout, (uint8_t *) str_bytes.data(), str_bytes.size());
        // str_bytes = read_text_message(socket, &privateKey);
        return;
    }
}

void client_business(int conn_fd, RSA &publicKey) {
    char buf[MESSAGE_LENGTH];

    printf("Waiting for input...\n");
    CodecIO socket(conn_fd);
    while (fgets(buf, MESSAGE_LENGTH, stdin)) {
        const vector<uint8_t> message(buf, buf + strlen(buf));
        write_text_message(socket, message, &publicKey);
        return;
    }
}
