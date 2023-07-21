#ifndef SGX_EML_HEXDUMP_H
#define SGX_EML_HEXDUMP_H

#include <cstdio>
#include <cstdint>

void hexdump(FILE *stream, uint8_t const *data, size_t len);

#endif //SGX_EML_HEXDUMP_H
