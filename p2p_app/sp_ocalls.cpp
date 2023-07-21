#include <cstdio>
#include "p2p_enclave_u.h"

using namespace std;

//enum OutputTarget {
//    TO_STDOUT,
//    TO_STDERR,
//    TO_APPLOG,
//};

int ocall_fputs(OutputTarget target, const char *str) {
    switch (target) {
        case TO_STDOUT:
            return fputs(str, stdout);
        case TO_STDERR:
            return fputs(str, stderr);
//        case TO_APPLOG:
//            return fputs(str, fplog);
//        default:
//            return fputs(str, fplog);
    }
    return -1;
}

void ocall_eputs(const char *macro_file, const char *macro_function, int macro_line, const char *message) {
    if (message) {
        printf("[%4d] %s: %s - %s\n", macro_line, macro_file, macro_function, message);
    } else {
        printf("[%4d] %s: %s\n", macro_line, macro_file, macro_function);
    }
}

