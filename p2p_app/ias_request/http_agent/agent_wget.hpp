#ifndef SGX_EML_AGENT_WGET_H
#define SGX_EML_AGENT_WGET_H

#include <sys/wait.h>
#include <system_error>
#include "agent.h"
#include "rio.hpp"
#include "httpparser/httpresponseparser.h"

using namespace httpparser;
using namespace std;

typedef int wget_exit_t;
#define WGET_EXIT_SUCCESS           0
#define WGET_EXIT_GENERIC_ERROR     1
#define WGET_EXIT_PARSE_ERROR       2
#define WGET_EXIT_IO_FAIL           3
#define WGET_EXIT_NETWORK_FAIL      4
#define WGET_EXIT_SSL_AUTH_FAIL     5
#define WGET_EXIT_SERVER_AUTH_FAIL  6
#define WGET_EXIT_PROTOCOL_ERROR    7
#define WGET_EXIT_SERVER_ERROR      8
#define WGET_EXIT_UNKNOWN           9


class AgentWget : protected Agent {

    bool verbose;
    bool debug;

    vector<string> build_wget_args(const map<string, string> &headers) {
        vector<string> args{"wget"};

        // Output options
        if (verbose) {
            args.emplace_back("--server-response");
            args.emplace_back("--verbose");
        } else {
            args.emplace_back("--quiet");
        }
        args.emplace_back("--output-document=-");
        args.emplace_back("--save-headers");
        args.emplace_back("--content-on-error");
        args.emplace_back("--no-http-keep-alive");

        // construct the headers
        for (const auto &item : headers) {
            string header = "--header=";

            header.append(item.first).append(":").append(item.second);
            args.push_back(header);
        }

        return args;
    }

public:
    const string name = "wget";

    explicit AgentWget(bool verbose = false, bool debug = false) : verbose(verbose), debug(debug) {}

    string GET(const string &url, const map<string, string> &headers, Response &resp) override {
        auto args = build_wget_args(headers);

        /* Add the URL */
        args.push_back(url);

        /* request */
        return request(args, resp);
    }

    string POST(const string &url, const map<string, string> &headers, const string &body, Response &resp) {
        auto args = build_wget_args(headers);

        /* Set POST body */
        string post_data = "--post-data=";
        post_data.append(body);
        args.push_back(post_data);

        /* Add the URL */
        args.push_back(url);

        /* request */
        return request(args, resp);
    }

private:
    string request(const vector<string> &args, Response &response) {
        // fprintf(stderr, "%s [%4d] %s: %d %d\n", __FILE__, __LINE__, __FUNCTION__, verbose, debug);
        if (verbose && debug) {
            fprintf(stderr, "%s [%4d] %s\n", __FILE__, __LINE__, __FUNCTION__);
            for (auto &arg : args) {
                cout << arg << " ";
            }
            cout << endl;
        }

        string resp;
        execute(args, resp);

        HttpResponseParser parser;
        HttpResponseParser::ParseResult result = parser.parse(response, resp.c_str(), resp.c_str() + resp.length());
        if (result != HttpResponseParser::ParsingCompleted) {
            return "";
        } else {
            return resp;
        }
    }

    wget_exit_t execute(const vector<string> &args, string &output) {
        /* Set up two pipes for reading from the child */
        int pipe_fd[2];
        if (pipe(pipe_fd) < 0) {
            throw system_error(errno, generic_category(), "wget - pipe");
        }

        /* Spawn the child process */
        int pid = fork();
        if (pid == -1) {
            throw system_error(errno, generic_category(), "wget - fork");
        } else if (pid == 0) {
            /* child process */

            while (dup2(pipe_fd[1], STDOUT_FILENO) < 0) {
                if (errno == EINTR) {
                    continue;
                } else {
                    throw system_error(errno, generic_category(), "wget - dup2");
                }
            }

            close(pipe_fd[1]);
            close(pipe_fd[0]);

            auto args_dup = args;
            /* Create the argument list */
            char **argv = (char **) malloc(args.size() + 1);
            for (size_t i = 0; i < args_dup.size(); i++) {
                argv[i] = &args_dup[i][0];
            }
            argv[args_dup.size()] = nullptr;

            execvp("wget", argv);

            throw system_error(errno, generic_category(), "wget - execvp");
        }

        /* parent process */
        close(pipe_fd[1]);

        /* Read until eol */
        RobustIO rio(pipe_fd[0]);
        rio.read_to_eof(output);

        /* This is a blocking wait */
        int status;
        while (waitpid(pid, &status, 0) == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                throw system_error(errno, generic_category(), "wget - waitpid");
            }
        }

        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else {
            throw system_error(errno, generic_category(), "wget");
        }
    }
};


#endif //SGX_EML_AGENT_WGET_H
