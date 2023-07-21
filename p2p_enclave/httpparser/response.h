/*
 * Copyright (C) Alex Nekipelov (alex@nekipelov.net)
 * License: MIT
 */

// Changes [JM] by John Mechalas <john.p.mechalas@intel.com>

#ifndef HTTPPARSER_RESPONSE_H
#define HTTPPARSER_RESPONSE_H

#include <string>
#include <vector>
#include <algorithm> // Added by JM
#include <tlibc/mbusafecrt.h>

namespace httpparser {

    struct Response {
        Response()
                : versionMajor(0), versionMinor(0), keepAlive(false), statusCode(0) {}

        struct HeaderItem {
            std::string name;
            std::string value;
        };

        int versionMajor;
        int versionMinor;
        std::vector<HeaderItem> headers;
        std::vector<char> content;
        bool keepAlive;

        unsigned int statusCode;
        std::string status;

        std::string inspect() const {
            std::string stream = "HTTP/";
            stream.append(std::to_string(versionMajor)).append(".").append(std::to_string(versionMinor)).append(" ")
                    .append(std::to_string(statusCode)).append(" ")
                    .append(status).append("\n");

            for (const auto &header : headers) {
                stream.append(header.name).append(": ").append(header.value).append("\n");
            }

            // Added "\n" so it prints like its received. - JM
            stream.append("\n").append(content.begin(), content.end()).append("\n");

            return stream;
        }

        // content_string() by JM
        std::string content_string() const {
            return std::string(content.begin(), content.end());
        }

        // headers_as_string() by JM
        std::string headers_as_string(const std::string &name) const {
            std::string stream;
            // Just in case we get more than one header with the same name.
            for (const auto &header : headers) {
                if (is_equal_ncase(header.name, name)) {
                    stream.append(header.value).append("\n");
                }
            }

            return stream;
        }

        // Case-insensitive string comparison - JM
        bool is_equal_ncase(std::string a, std::string b) const {
            transform(a.begin(), a.end(), a.begin(), ::toupper);
            transform(b.begin(), b.end(), b.begin(), ::toupper);
            return (a == b);
        }

    };

} // namespace httpparser

#endif // HTTPPARSER_RESPONSE_H

