#include <cstdio>
#include <sgx_urts.h>
#include <sgx_utils/sgx_utils.h>
#include "config.h"
#include "protocol.h"
#include "socket.hpp"
#include "timelog.hpp"
#include "codec_io.hpp"
#include "isv_att_enclave.hpp"
#include <hexdump.h>
#include "business.h"

void client_attestation(int fd, sgx_enclave_id_t eid, const UserArgs &userArgs);

void fprint_usage(FILE *fp, const char *executable) {
    fprintf(fp, "Usage: \n");
    fprintf(fp, "    %s <toml config> <host> <port>", executable);
}


int main(int argc, char const *argv[]) {
    if (argc < 2) {
        fprint_usage(stderr, argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *toml = argv[1];
    UserArgs userArgs = UserArgs(toml);

    sgx_enclave_id_t eid;

    /* Enclave Initialization */
    if (initialize_enclave(&eid, "Enclave_p2p.token", "Enclave_p2p.signed.so") < 0) {
        printf("Fail to initialize enclave.\n");
        return 1;
    }
    

    if (userArgs.get_sgx_debug()) {
        fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
    }

    if (argc == 4) {
        const char *host = argv[2];
        const char *port = argv[3];

        Socket socket(Socket::SOCKET_CLIENT, host, port);
        cout << "Connected to EML " << host << ":" << port << endl;

        client_attestation(socket.get_file_decriptor(), eid, userArgs);
        client_business(socket.get_file_decriptor(), eid);

        cout << "Disconnecting ... " << endl;
        return 0;
    }

    if (userArgs.get_sgx_debug()) {
        fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
    }

    fprint_usage(stdout, argv[0]);
    return -1;
}

///////////////////////////////////////////////////////////////////////////////
using bytes = vector<uint8_t>;

void client_attestation(int fd, sgx_enclave_id_t eid, const UserArgs &userArgs) {
    CodecIO codecIo(fd);
    isv_att_enclave isvAttEnclave(eid, userArgs);
    {
        TimeLog timer;

        puts("/**************** Initiating Remote Attestation ... ****************/\n");

        {
            /**************** Generate message 0 and 1 ****************/
            const uint32_t msg0 = isvAttEnclave.generate_msg0();
            bytes msg01_bytes((uint8_t *) &msg0, (uint8_t *) &msg0 + sizeof(uint32_t));
            const bytes msg1_bytes = isvAttEnclave.generate_msg1();

            /**************** Send message 0 and 1 ****************/
            msg01_bytes.insert(msg01_bytes.end(), msg1_bytes.begin(), msg1_bytes.end());

            if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
                puts("/**************** Generate message 0 and 1 ****************/\n");
                hexdump(stdout, msg01_bytes.data(), msg01_bytes.size());
            }

            codecIo.write(msg01_bytes);
        }

        {

            /**************** Receive message 2 ****************/
            bytes msg2_bytes = codecIo.read();

            if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
                puts("/**************** Receive message 2 ****************/\n");
                hexdump(stdout, msg2_bytes.data(), msg2_bytes.size());
            }

            /**************** Generate message 3 ****************/
            const bytes msg3_bytes = isvAttEnclave.generate_msg3(msg2_bytes);

            if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
                puts("/**************** Generate message 0 and 1 ****************/\n");
                hexdump(stdout, msg3_bytes.data(), msg3_bytes.size());
            }
            /**************** Send message 3 ****************/
            codecIo.write(msg3_bytes);

            if (userArgs.get_sgx_debug()) {
                fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
            }

        }

        cout << "Remote Attestation ";
    }


    /**************** Receive message 4 ****************/
    bytes msg4_bytes = codecIo.read();
    const ra_msg4_t &msg4 = *(ra_msg4_t *) msg4_bytes.data();

    if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
        puts("/**************** Receive message 4 ****************/\n");
        hexdump(stdout, msg4_bytes.data(), msg4_bytes.size());
    }

    if (msg4.status == Trusted) {
        puts("**************** Remote Attestation Succeed ****************/\n");
        puts("\033[31m/**************** Trusted ****************/\n\033[0m");

        puts("/**************** Hashing Ephemeral elliptic curve Diffie-Hellman key ...  ****************/\n");

        auto key_hash = isvAttEnclave.generate_key();
        hexdump(stdout, key_hash.data(), key_hash.size());
    }
}
