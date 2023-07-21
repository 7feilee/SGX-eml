#include <cstdio>
#include <sgx_urts.h>
#include <sgx_utils/sgx_utils.h>
#include "config.h"
#include "protocol.h"
#include "socket.hpp"
#include "timelog.hpp"
#include "codec_io.hpp"
#include "isv_att_enclave.hpp"
#include "sp_att_enclave.hpp"
#include "ias_request/http_agent/agent_wget.hpp"
#include "ias_request/httpparser/response.h"
#include "ias_request/ias_request.hpp"
#include <hexdump.h>
#include <thread>
#include <shared_mutex>
#include <future>
#include <chrono>
#include "business.h"

shared_mutex ra_status_mutex;
bool ra_status = false;

void server_attestation(int fd, sgx_enclave_id_t eid, const UserArgs &userArgs);
void client_attestation(int fd, sgx_enclave_id_t eid, const UserArgs &userArgs);

void fprint_usage(FILE *fp, const char *executable) {
    fprintf(fp, "Usage: \n");
    fprintf(fp, "    %s <toml config> <app_port> <enclave_port>", executable);
}

sgx_status_t ret_status;

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
        const char *app_port = argv[2];
        const char *enclave_port = argv[3];

        // Thread for the first server
        std::thread server1([&, app_port]{
            Socket socket(Socket::SOCKET_SERVER, "", app_port);
            string client_hostname, client_port;

            if (userArgs.get_sgx_debug()) {
                fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
            }

            while (true) {
                int fd = socket.serve(client_hostname, client_port);
                if(fd == -1) {
                    cout << "Failing to connect App Owner " << client_hostname << ":" << client_port << endl;
                    break;
                }

                cout << "Connected to App Owner " << client_hostname << ":" << client_port << endl;

                // spawn a new thread for each client connection
                thread client_thread([fd, eid, &userArgs, &client_hostname, &client_port]() {
                    
                    client_attestation(fd, eid, userArgs);

                    Socket::disconnect(fd);
                    cout << "Disconnected from " << client_hostname << ":" << client_port << endl;
                });

                // detach the thread so that it can operate independently and we can immediately
                // accept new connections. This avoids blocking the main loop.
                client_thread.detach();
            }
        });

        // Thread for the second server
        std::thread server2([&, enclave_port]{
            Socket socket(Socket::SOCKET_SERVER, "", enclave_port);
            string client_hostname, client_port;

            if (userArgs.get_sgx_debug()) {
                fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
            }

            while (true) {
                int fd = socket.serve(client_hostname, client_port);
                if(fd == -1) {
                    cout << "Failing to connect App Enclave " << client_hostname << ":" << client_port << endl;
                    continue;
                }
                bool local_copy_of_ra_status;
                {
                    std::shared_lock lock(ra_status_mutex);
                    local_copy_of_ra_status = ra_status;
                }
                if(!local_copy_of_ra_status){
                    Socket::disconnect(fd);
                    cout << "Failing to App Owner's Remote Attestation. Disconnecting App Enclave " << client_hostname << ":" << client_port << endl;
                    continue;
                }

                cout << "Connected to App Enclave " << client_hostname << ":" << client_port << endl;

                // spawn a new thread for each client connection
                thread client_thread([fd, eid, &userArgs, &client_hostname, &client_port]() {
                    {
                        server_attestation(fd, eid, userArgs);
                    }
                    
                    const auto timeout_duration = std::chrono::seconds(10);  // 10 seconds

                    auto future = std::async(std::launch::async, server_business, fd, eid);
                    if (future.wait_for(timeout_duration) == std::future_status::timeout) {
                        std::cout << "Timeout occurred. Disconnecting..." << std::endl;
                    } else {
                        std::cout << "Disconnected" << std::endl;
                    }

                    Socket::disconnect(fd);
                    cout << "Disconnected from " << client_hostname << ":" << client_port << endl;
                });

                // detach the thread so that it can operate independently and we can immediately
                // accept new connections. This avoids blocking the main loop.
                client_thread.detach();
            }
        });

        server1.join();
        server2.join();

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

void server_attestation(int fd, sgx_enclave_id_t eid, const UserArgs &userArgs) {
    CodecIO codecIo(fd);
    sp_att_enclave spAttEnclave(eid, userArgs);
    
    {
        TimeLog timer;

        puts("/**************** Initiating Remote Attestation ... ****************/\n");

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
            const bytes msg2_bytes = spAttEnclave.process_msg01(msg01_bytes, sigrl);

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
            const bytes msg4_bytes = spAttEnclave.process_msg3(msg3_bytes, str_response);

            if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
                puts("/**************** Generate message 4 ****************/\n");
                hexdump(stdout, msg4_bytes.data(), msg4_bytes.size());
            }

            codecIo.write(msg4_bytes);
            const ra_msg4_t &msg4 = *(ra_msg4_t *) msg4_bytes.data();
            if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
                puts("/**************** Receive message 4 ****************/\n");
                hexdump(stdout, msg4_bytes.data(), msg4_bytes.size());
            }

            if (msg4.status == Trusted){

                puts("**************** Remote Attestation Succeed ****************/\n");
                puts("\033[31m/**************** Trusted ****************/\n\033[0m");

            if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
                puts("/**************** Getting sp's secret ****************/\n");
            }

            puts("/**************** Getting(Unsealing) App Owner's secret ****************/\n");
            auto sp_secret = spAttEnclave.get_sp_secret();
            hexdump(stdout, sp_secret.data(), sp_secret.size());

            puts("/**************** Hashing Ephemeral elliptic curve Diffie-Hellman key ...  ****************/\n");

            auto key_hash = spAttEnclave.generate_key();
            hexdump(stdout, key_hash.data(), key_hash.size());
            }
        }
        cout << "Remote Attestation ";
    }

}

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
        unique_lock lock(ra_status_mutex);
        ra_status = true;
        puts("**************** Remote Attestation Succeed ****************/\n");
        puts("\033[31m/**************** Trusted ****************/\n\033[0m");

    if (userArgs.get_sgx_verbose() && userArgs.get_sgx_debug()) {
        puts("/**************** Saving sp's secret ****************/\n");
    }
        puts("/**************** Sealing App Owner's secret ****************/\n");

        isvAttEnclave.save_secret(msg4.secret.payload, msg4.secret.payload_tag);
        
    }else{
        puts("**************** Remote Attestation Failed ****************/\n");
        puts("\033[31m/**************** UNTRUST ****************/\n\033[0m");

        unique_lock lock(ra_status_mutex);
        ra_status = false;
    }
}

