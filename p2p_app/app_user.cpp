#include <cstdio>
#include "socket.hpp"
#include "codec_io.hpp"
#include "business.h"

void fprint_usage(FILE *fp, const char *executable) {
    fprintf(fp, "Usage: \n");
    fprintf(fp, "    %s <public_key.pem> <host> <port>", executable);
}

// Function to load an RSA public key from a file
RSA* load_rsa_public_key(const char* publicKeyFile) {

    BIO* BioPublic = BIO_new_file(publicKeyFile, "r+");
    RSA *rsaPublicKey;
    rsaPublicKey = PEM_read_bio_RSAPublicKey(BioPublic, &rsaPublicKey, nullptr, nullptr);
	BIO_free_all(BioPublic);

    if (!rsaPublicKey) {
        std::cerr << "Error reading public key" <<  ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return nullptr;
    }

    return rsaPublicKey;
}


int main(int argc, char const *argv[]) {
    if (argc < 2) {
        fprint_usage(stderr, argv[0]);
        exit(EXIT_FAILURE);
    }


    if (argc == 4) {
        const char *publicKeyFile = argv[1];
        const char *host = argv[2];
        const char *port = argv[3];

        RSA *rsaServerPublicKey = load_rsa_public_key(publicKeyFile);

        Socket socket(Socket::SOCKET_CLIENT, host, port);

        cout << "Connected to App Enclave " << host << ":" << port << endl;

        client_business(socket.get_file_decriptor(), *rsaServerPublicKey);

        cout << "Disconnecting from " << host << ":" << port << endl;

        return 0;
    }

    fprint_usage(stdout, argv[0]);
    return -1;

}