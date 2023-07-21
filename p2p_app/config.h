#ifndef SGX_EML_CONFIG_H
#define SGX_EML_CONFIG_H

#include <string>
#include <map>
#include <array>
#include <sgx_key_exchange.h>

using namespace std;


typedef struct config_struct {
    char mode;
    uint32_t flags;
    sgx_spid_t spid;
    sgx_ec256_public_t pubkey;
    sgx_quote_nonce_t nonce;
    char *server;
    char *port;
} config_t;


struct UserArgs {

    static int parse_int(const string &str);

    template<size_t CharLength>
    array<char, CharLength> check_hstr(const string &hex_str);

    template<class T>
    T search_numeric(const string &name, T default_value) const;

    template<class T>
    T search_numeric(const string &name) const;

    map<string, int> numeric_map;
    map<string, array<char, 32>> h32_map;
    array<uint8_t, 32> POLICY_MRSIGNER{};
    array<uint8_t, 32> POLICY_MRENCLAVE{};
    map<string, string> str_map;

public:
    explicit UserArgs(const string &toml);

    bool get_query_ias_production() const;

    sgx_spid_t get_spid() const;

    sgx_quote_sign_type_t get_quote_type() const;

    bool get_client_random_nonce() const;

    bool get_client_use_platform_services() const;

    array<char, 32> get_ias_primary_subscription_key() const;

    array<char, 32> get_ias_secondary_subscription_key() const;

    array<uint8_t, 32> get_policy_mrsigner() const;

    array<uint8_t, 32> get_policy_mrenclave() const;

    uint16_t get_policy_product_id() const;

    uint16_t get_policy_isv_min_svn() const;

    bool get_policy_allow_debug() const;

    bool get_policy_allow_configuration_needed() const;

    bool get_sgx_verbose() const;

    bool get_sgx_debug() const;
};

#endif //SGX_EML_CONFIG_H
