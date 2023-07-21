#include "io.h"
#include <cstdio>
#include <tlibc/mbusafecrt.h>
//typedef int (*PRINT_TO_STDOUT_STDERR_CB)(Stream_t stream, const char* fmt, va_list);

int ocall_ssl_fprintf(Stream_t target, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    char buffer[IO_BUFFER_SIZE];
    sprintf_s(buffer, IO_BUFFER_SIZE, fmt, ap);

            va_end(ap);

    int rv = 0;
    if (target == STREAM_STDERR) {
        ocall_fputs(&rv, TO_STDERR, buffer);
    } else {
        ocall_fputs(&rv, TO_STDOUT, buffer);
    }

    return rv;
}

int ocall_fprintf(OutputTarget target, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    char buffer[IO_BUFFER_SIZE];
    sprintf_s(buffer, IO_BUFFER_SIZE, fmt, ap);

            va_end(ap);

    int rv = 0;
    ocall_fputs(&rv, target, buffer);
    return rv;
}
