#include <cstdio>
#include "config.h"
#include "protocol.h"
#include "socket.hpp"
#include "timelog.hpp"
#include "codec_io.hpp"
#include "sp_att.hpp"
#include "ias_request/http_agent/agent_wget.hpp"
#include "ias_request/httpparser/response.h"
#include "ias_request/ias_request.hpp"
#include <hexdump.h>

void server_attestation(int fd, const UserArgs &userArgs, const vector<uint8_t> &privateKeyBytes);

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


    if (argc == 4) {
        const char *host = argv[2];
        const char *port = argv[3];

        puts("/**************** Generating App Owner's RSA key-pair (pk, sk) ****************/\n");
        
        const char* publicKeyFile = "public_key.pem";
        vector<uint8_t> privateKeyBytes;

        if(!generateRSAKeyPair(publicKeyFile, privateKeyBytes)){
            cout << "App Keygen failed" << endl;
        }

        if (userArgs.get_sgx_debug()) {
            fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
        }

        Socket socket(Socket::SOCKET_CLIENT, host, port);

        if (userArgs.get_sgx_debug()) {
            fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
        }

        cout << "Connected to EML " << host << ":" << port << endl;

        server_attestation(socket.get_file_decriptor(), userArgs, privateKeyBytes);

        cout << "Disconnecting from " << host << ":" << port << endl;

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

void server_attestation(int fd, const UserArgs &userArgs, const vector<uint8_t> &privateKeyBytes) {
    TimeLog timer;
    CodecIO codecIo(fd);
    sp_att spAtt(userArgs);

    puts("/**************** Initiating Remote Attestation ****************/\n");

    IAS_Request iasRequest(userArgs.get_ias_primary_subscription_key(), userArgs.get_ias_secondary_subscription_key(),
                           userArgs.get_query_ias_production());

    if (userArgs.get_sgx_debug()) {
        fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
    }
    AgentWget agent(userArgs.get_sgx_verbose(), userArgs.get_sgx_debug());

    if (userArgs.get_sgx_debug()) {
        fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
    }

    {
        /**************** Receive message 0 and 1 ****************/
        bytes msg01_bytes = codecIo.read();
        const ra_msg01_t &msg01 = *(const ra_msg01_t *) msg01_bytes.data();

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Receive message 0 and 1 ****************/\n");
            hexdump(stdout, msg01_bytes.data(), msg01_bytes.size());
        }

        /**************** Request sigrl ****************/
        httpparser::Response sigrl_response;
        string sigrl = iasRequest.sigrl((Agent *) &agent, *(uint32_t *) msg01.msg1.gid, sigrl_response);

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Request sigrl ****************/\n");
            puts(sigrl.c_str());
        }

        /**************** Process message 0 and 1, generate message 2 ****************/
        const bytes msg2_bytes = spAtt.process_msg01(msg01_bytes, sigrl);

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Generate message 2 ****************/\n");
            hexdump(stdout, msg2_bytes.data(), msg2_bytes.size());
        }

        /**************** Send message 2 ****************/
        codecIo.write(msg2_bytes);
    }

    {
        /**************** Read message 3 ****************/
        bytes msg3_bytes = codecIo.read();
        const sgx_ra_msg3_t &msg3 = *(sgx_ra_msg3_t *) msg3_bytes.data();

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Receive message 3 ****************/\n");
            hexdump(stdout, msg3_bytes.data(), msg3_bytes.size());
        }

        /**************** Request attestation report ****************/
        bytes quote_bytes(msg3.quote, msg3.quote + msg3_bytes.size() - sizeof(sgx_ra_msg3_t));
        map<Attestation_Evidence_Payload, vector<uint8_t >> payload;
        payload.insert({isvEnclaveQuote, quote_bytes});

        httpparser::Response att_response;
        string str_response = iasRequest.report((Agent *) &agent, payload, att_response);

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Request attestation report ****************/\n");
            puts(str_response.c_str());
        }

        /**************** Process attestation report, generate message 4 ****************/
        const bytes msg4_bytes = spAtt.process_msg3(msg3_bytes, privateKeyBytes, str_response);

        if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
            puts("/**************** Generate message 4 ****************/\n");
        }

        codecIo.write(msg4_bytes);

    }
    cout << "Remote Attestation ";

}
