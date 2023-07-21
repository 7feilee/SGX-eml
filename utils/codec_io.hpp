#ifndef SOCKET_CODEC_IO_H
#define SOCKET_CODEC_IO_H

#include <vector>
#include <string>

#include "rio.hpp"
#include <cppcodec/cppcodec/hex_lower.hpp>

class CodecIO {
    RobustIO rio;

    using codec = cppcodec::hex_lower;
    using bytes = std::vector<uint8_t>;

public:
    explicit CodecIO(int fd) : rio(RobustIO(fd)) {}

    CodecIO(int read_fd, int write_fd) : rio(RobustIO(read_fd, write_fd)) {}

    bytes read() {
        std::string buffer;
        rio.readline_b(buffer);
        while (buffer.back() == '\n') {
            buffer.pop_back();
        }

        return codec::decode(buffer);
    }

    void write(const bytes &data) {
        std::string buffer = codec::encode(data);

        int rc = rio.writeline(buffer);
        if (rc < 0) {
            // throw something
        }
    }
};

#endif //SOCKET_CODEC_IO_H
