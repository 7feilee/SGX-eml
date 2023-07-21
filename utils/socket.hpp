//
// http://csapp.cs.cmu.edu/3e/ics3/code/include/csapp.h
// http://csapp.cs.cmu.edu/3e/ics3/code/src/csapp.c
//

#ifndef SOCKET_SOCKET_UTILS_HPP
#define SOCKET_SOCKET_UTILS_HPP


#include <exception>
#include <string>
#include <utility>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <system_error>
#include <iostream>

using namespace std;

class getaddrinfo_error : public exception {
    string _what;
public:
    getaddrinfo_error(const string &caption, int error_code) {
        char buffer[1024];
        sprintf(buffer, "%s: %s\n", caption.c_str(), gai_strerror(error_code));
        _what.assign(buffer);
    }

    getaddrinfo_error(const string &host, const string &port, int error_code) {
        char buffer[1024];
        sprintf(buffer, "getaddrinfo failed (%s:%s): %s\n", host.c_str(), port.c_str(), gai_strerror(error_code));
        _what.assign(buffer);
    }

    const char *what() const noexcept override {
        return _what.c_str();
    }
};


class Socket {
    static const int LISTENQ = 1024;                            // Second argument to listen()
    typedef struct addrinfo addr_info_t;
    typedef struct sockaddr sock_addr_t;
    int fd = -1;

/*
 * open_clientfd - Open connection to server at <hostname, port> and
 *     return a socket descriptor ready for reading and writing. This
 *     function is reentrant and protocol-independent.
 */
    static int open_clientfd(const char *hostname, const char *port) {
        /* Get a list of potential server addresses */
        addr_info_t hints{};
        memset(&hints, 0, sizeof(addr_info_t));
        hints.ai_socktype = SOCK_STREAM;                        // Open a connection
        hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;        // Recommended for connections using a numeric port arg.

        addr_info_t *list_p;
        GetAddressInfo(hostname, port, &hints, &list_p);

        try {
            /* Walk the list for one that we can successfully connect to */
            for (addr_info_t *p = list_p; p; p = p->ai_next) {
                /* Create a socket descriptor */
                int client_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
                if (client_fd < 0) {
                    continue;                                   // Socket failed, try the next
                }

                /* Connect to the server */
                if (connect(client_fd, p->ai_addr, p->ai_addrlen) != -1) {
                    freeaddrinfo(list_p);                       // Success
                    return client_fd;
                }

                /* Connect failed, try another */
                Close(client_fd);
            }
        } catch (...) {
            freeaddrinfo(list_p);
            throw;
        }

        throw system_error(errno, generic_category(), "Open_clientfd error");
    }


/*
 * open_listenfd - Open and return a listening socket on port. This
 *     function is reentrant and protocol-independent.
 */
    static int open_listenfd(const char *port) {
        /* Get a list of potential server addresses */
        addr_info_t hints;
        memset(&hints, 0, sizeof(addr_info_t));
        hints.ai_socktype = SOCK_STREAM;                                // Accept connections
        hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE | AI_ADDRCONFIG;   // using port number on any IP address

        addrinfo *list_p;
        GetAddressInfo(nullptr, port, &hints, &list_p);

        try {
            /* Walk the list for one that we can bind to */
            for (addrinfo *p = list_p; p; p = p->ai_next) {
                /* Create a socket descriptor */
                int listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
                if (listen_fd < 0) {
                    continue;                                       // Socket failed, try the next
                }
                /* Eliminates "Address already in use" error from bind */
                int opt_val = 1;
                setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &opt_val, sizeof(int));

                /* Bind the descriptor to the address */
                if (bind(listen_fd, p->ai_addr, p->ai_addrlen) == 0) {
                    freeaddrinfo(list_p);

                    if (listen(listen_fd, LISTENQ) < 0) {
                        Close(listen_fd);
                        throw system_error(errno, generic_category(), "open_client_fd: close failed");
                    }

                    return listen_fd;                               // Success
                }

                /* Bind failed, try the next */
                Close(listen_fd);
            }

        } catch (...) {
            freeaddrinfo(list_p);
            throw;
        }

        throw system_error(errno, generic_category(), "Open_listenfd error");
    }

    static void Shutdown(int file_descriptor) {
        if (shutdown(file_descriptor, SHUT_RDWR) < 0) {
            throw system_error(errno, generic_category(), "close file descriptor failed");
        }
    }

    static void Close(int file_descriptor) {
        if (close(file_descriptor) < 0) {
            throw system_error(errno, generic_category(), "close file descriptor failed");
        }
    }

    static void GetAddressInfo(const char *name, const char *service, const addr_info_t *req, addr_info_t **pai) {
        int rc = getaddrinfo(name, service, req, pai);
        if (rc != 0) {
            throw getaddrinfo_error(name, service, rc);
        }
    }

    static int Accept(int file_descriptor, sock_addr_t *addr, socklen_t *addr_len) {
        int rc = accept(file_descriptor, addr, addr_len);

        if (rc < 0) {
            throw system_error(errno, generic_category(), "Accept error");
        }

        return rc;
    }

public:
    enum Role {
        SOCKET_SERVER, SOCKET_CLIENT
    };

    Socket(Role role, const string &host, const string &port) {
        switch (role) {

            case SOCKET_SERVER:
                fd = open_listenfd(port.c_str());
                break;
            case SOCKET_CLIENT:
                fd = open_clientfd(host.c_str(), port.c_str());
                break;
            default:
                throw invalid_argument("Unknown socket role");
        }
    }

    ~Socket() {
        Close(fd);
    }

    int serve(string &client_hostname, string &client_port) {


        static const socklen_t MAX_LINE = 2048;

        struct sockaddr_storage client_addr{};
        socklen_t client_len = sizeof(struct sockaddr_storage);
        int conn_fd = Accept(fd, (sock_addr_t *) &client_addr, &client_len);
        char c_host[MAX_LINE];
        struct sockaddr_in *client_addr_in = (struct sockaddr_in *)&client_addr;
        inet_ntop(AF_INET, &(client_addr_in->sin_addr), c_host, INET_ADDRSTRLEN);
        int c_port = ntohs(client_addr_in->sin_port);
        client_hostname.assign(c_host);
        client_port = to_string(c_port);

        return conn_fd;
    }

    static void disconnect(int conn_fd) {
        Shutdown(conn_fd);
        Close(conn_fd);
    }

    int get_file_decriptor() const {
        return fd;
    }

};


#endif //SOCKET_SOCKET_UTILS_HPP
