#include <openssl/bio.h>
#include <openssl/evp.h>
#include "base64.h"

using namespace std;

//string base64_encode(const vector<uint8_t> &msg) {
//    BIO *bio_b64 = BIO_new(BIO_f_base64());
//    BIO *bio_mem = BIO_new(BIO_s_mem());
//    string output = "";
//
//    do {
//        /* Single line output */
//        BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
//
//        BIO_push(bio_b64, bio_mem);
//
//        if (BIO_write(bio_b64, msg.data(), msg.size()) == -1) {
//            break;
//        }
//        BIO_flush(bio_b64);
//
//        char *p_data;
//        size_t len = BIO_get_mem_data(bio_mem, &p_data);
//        output.assign(p_data, p_data + len);
//
//    } while (false);
//
//    BIO_free(bio_mem);
//    BIO_free(bio_b64);
//
//    return output;
//}

vector<uint8_t> base64_decode(const string &msg) {
    BIO *bio_b64 = BIO_new(BIO_f_base64());
    BIO *bio_mem = BIO_new_mem_buf(msg.data(), msg.size());
    vector<uint8_t> output;

    /* Single line output */
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_push(bio_b64, bio_mem);

    output.resize(msg.size());
    size_t len = BIO_read(bio_b64, &output[0], msg.size());
    output.resize(len);

    BIO_free(bio_mem);
    BIO_free(bio_b64);

    return output;
}
