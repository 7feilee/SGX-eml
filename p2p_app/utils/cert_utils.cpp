#include <openssl/pem.h>
#include "cert_utils.h"
#include "urldecode.h"
#include <openssl/err.h>
#include <exception>
#include <openssl/x509.h>

using namespace std;

typedef STACK_OF(X509) X509_STACK;

class OpenSSLException : public exception {
    string message;
public:
    explicit OpenSSLException(unsigned long err_code) : message(ERR_error_string(err_code, nullptr)) {
    }

    const char *what() const noexcept override {
        return message.c_str();
    };
};

OpenSSLException get_openssl_error() {
    return OpenSSLException(ERR_get_error());
}

/*==========================================================================
 * Certificate verification
 *========================================================================== */

X509 *cert_load(const string &pem_data) {
    BIO *bio_mem = nullptr;

    try {
        X509 *cert;

        bio_mem = BIO_new(BIO_s_mem());
        if (bio_mem == nullptr) {
            throw get_openssl_error();
        }

        if (BIO_write(bio_mem, pem_data.c_str(), pem_data.length()) != pem_data.length()) {
            throw get_openssl_error();
        }

        cert = PEM_read_bio_X509(bio_mem, nullptr, nullptr, nullptr);

        if (cert == nullptr) {
            throw get_openssl_error();
        } else {
            BIO_free(bio_mem);
            return cert;
        }
    } catch (...) {
        if (bio_mem != nullptr)
            BIO_free(bio_mem);
        throw;
    }
}


X509 *cert_load_Intel_SGX_Attestation_RootCA() {
    static const string Intel_SGX_Attestation_RootCA =
            "-----BEGIN CERTIFICATE-----\n"
            "MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\n"
            "BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\n"
            "BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\n"
            "YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy\n"
            "MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL\n"
            "U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD\n"
            "DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G\n"
            "CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e\n"
            "LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh\n"
            "rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT\n"
            "L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe\n"
            "NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ\n"
            "byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H\n"
            "afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf\n"
            "6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM\n"
            "RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX\n"
            "MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50\n"
            "L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW\n"
            "BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr\n"
            "NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq\n"
            "hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir\n"
            "IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ\n"
            "sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi\n"
            "zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra\n"
            "Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA\n"
            "152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB\n"
            "3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O\n"
            "DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv\n"
            "DaVzWh5aiEx+idkSGMnX\n"
            "-----END CERTIFICATE-----\n";

    return cert_load(Intel_SGX_Attestation_RootCA);
}


X509_STORE *cert_init_ca(X509 *cert) {
    X509_STORE *store;

    store = X509_STORE_new();
    if (store == nullptr) {
        throw get_openssl_error();
    }

    if (X509_STORE_add_cert(store, cert) != 1) {
        X509_STORE_free(store);
        throw get_openssl_error();
    }

    return store;
}

/*
 * Verify cert chain against our CA in store. Assume the first cert in
 * the chain is the one to validate. Note that a store context can only
 * be used for a single verification so we need to do this every time
 * we want to validate a cert.
 */

bool cert_verify(X509_STORE *store, X509_STACK *chain) {
    X509_STORE_CTX *ctx = nullptr;
    X509 *cert = sk_X509_value(chain, 0);

    try {

        ctx = X509_STORE_CTX_new();
        if (ctx == nullptr) {
            throw get_openssl_error();
        }

        if (X509_STORE_CTX_init(ctx, store, cert, chain) != 1) {
            throw get_openssl_error();
        }

        int rv = X509_verify_cert(ctx);

        if (rv != 1 && rv != 0) {
            throw get_openssl_error();
        }

        X509_STORE_CTX_free(ctx);

        return rv;
    } catch (...) {
        if (ctx != nullptr)
            X509_STORE_CTX_free(ctx);
    }
}

/*
 * Take an array of certificate pointers and build a stack.
 */

X509_STACK *cert_stack_build(const vector<X509 *> &cert_vec) {
    X509_STACK *stack;

    stack = sk_X509_new_null();
    if (stack == nullptr) {
        throw get_openssl_error();
    }

    for (auto p_cert:cert_vec) {
        sk_X509_push(stack, p_cert);
    }

    return stack;
}


int sha256_verify(const unsigned char *msg, size_t mlen, unsigned char *sig, size_t sigsz, EVP_PKEY *pkey) {
    EVP_MD_CTX *ctx = nullptr;

    try {
        ctx = EVP_MD_CTX_new();
        if (ctx == nullptr) {
            throw get_openssl_error();
        }

        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
            throw get_openssl_error();
        }

        if (EVP_DigestVerifyUpdate(ctx, msg, mlen) != 1) {
            throw get_openssl_error();
        }

        int rv = EVP_DigestVerifyFinal(ctx, sig, sigsz);
        if (rv == 0 || rv == 1) {
            EVP_MD_CTX_free(ctx);
            return rv;
        } else {
            throw get_openssl_error();
        }
    } catch (...) {
        if (ctx != nullptr) {
            EVP_MD_CTX_free(ctx);
        }
        throw;
    }
}

char *base64_decode(const char *msg, size_t *sz) {
    BIO *b64, *bio_mem;
    char *buf;
    size_t len = strlen(msg);

    buf = (char *) malloc(len + 1);
    if (buf == nullptr) return nullptr;
    memset(buf, 0, len + 1);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio_mem = BIO_new_mem_buf(msg, (int) len);

    BIO_push(b64, bio_mem);

    *sz = BIO_read(b64, buf, (int) len);
    if (*sz == -1) {
        free(buf);
        return nullptr;
    }

    BIO_free_all(bio_mem);

    return buf;
}


sgx_status_t verify_certificate(const httpparser::Response &response, attestation_error_t &att_error) {
    /*
     * The response body has the attestation report. The headers have
     * a signature of the report, and the public signing certificate.
     * We need to:
     *
     * 1) Verify the certificate chain, to ensure it's issued by the
     *    Intel CA (passed with the -A option).
     *
     * 2) Extract the public key from the signing cert, and verify
     *    the signature.
     */
    att_error = NoErrorInformation;

    X509 *sign_cert = nullptr; /* The first cert in the list */

    X509_STACK *stack = nullptr;
    X509 *ias_root_ca = nullptr;
    X509_STORE *store = nullptr;
    vector<X509 *> cert_vec;

    try {
        try {
            // Get the certificate chain from the headers
            string cert_chain = response.headers_as_string("X-IASReport-Signing-Certificate");
            if (cert_chain.empty()) {
                att_error = ATTR_SigningCertificateNotFound;
                return SGX_ERROR_UNEXPECTED;
            }

            // URL decode
            cert_chain = url_decode(cert_chain);

            // Build the cert stack. Find the positions in the string where we have a BEGIN block.
            size_t cstart = 0, cend = 0;
            while (cend != string::npos) {
                cend = cert_chain.find("-----BEGIN", cstart + 1);

                size_t len = ((cend == string::npos) ? cert_chain.length() : cend) - cstart;
                cert_vec.push_back(cert_load(cert_chain.substr(cstart, len)));

                cstart = cend;
            }
        } catch (...) {
            att_error = ATTR_CertificateHeaderInvalid;
            throw;
        }


        // Create a X509_STACK stack from our certs
        stack = cert_stack_build(cert_vec);

        // Now verify the signing certificate
        ias_root_ca = cert_load_Intel_SGX_Attestation_RootCA();
        store = cert_init_ca(ias_root_ca);


        size_t i = 0;
        if (cert_verify(store, stack)) {
            sign_cert = cert_vec[0];
            i = 1;
        } else {
            att_error = ATTR_CertificationVerifyFailed;
            throw;
        }

        // free
        sk_X509_free(stack);
        X509_STORE_free(store);
        X509_free(ias_root_ca);

        for (; i < cert_vec.size(); i++) {
            X509_free(cert_vec[i]);
        }

    } catch (...) {
        sk_X509_free(stack);
        X509_STORE_free(store);
        X509_free(ias_root_ca);

        for (auto &i : cert_vec) {
            X509_free(i);
        }
        return SGX_ERROR_UNEXPECTED;
    }

    if (sign_cert == nullptr) {
        return SGX_ERROR_UNEXPECTED;
    }


    EVP_PKEY *pkey = nullptr;
    unsigned char *sig = nullptr;
    size_t sig_size;


    try {
        // The signing cert is valid, so extract and verify the signature
        string sig_string = response.headers_as_string("X-IASReport-Signature");
        if (sig_string.empty()) {
            att_error = ATTR_SignatureNotFound;
            throw;
        }

        sig = (unsigned char *) base64_decode(sig_string.c_str(), &sig_size);
        if (sig == nullptr) {
            att_error = ATTR_SignatureInvalid;
            throw get_openssl_error();
        }

        /*
         * The report body is SHA256 signed with the private key of the
         * signing cert.  Extract the public key from the certificate and
         * verify the signature.
         */

        pkey = X509_get_pubkey(sign_cert);
        if (pkey == nullptr) {
            att_error = ATTR_OpensslError;
            throw get_openssl_error();
        }

        string content = response.content_string();
        if (sha256_verify((const unsigned char *) content.c_str(), content.length(), sig, sig_size, pkey)) {
            att_error = NoErrorInformation;
        } else {
            att_error = ATTR_SignatureVerifyFailed;
        }

        free(sig);
        X509_free(sign_cert);
    } catch (...) {
        free(sig);
        X509_free(sign_cert);
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}
