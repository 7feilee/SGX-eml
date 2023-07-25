#include <iostream>
#include <cstdlib>
#include "cppcodec/cppcodec/hex_default_lower.hpp"
#include <cpptoml.h>
#include "config.h"

UserArgs::UserArgs(const string &toml) {
    shared_ptr<cpptoml::table> toml_config;
    toml_config = cpptoml::parse_file(toml);

    enum UserVarType {
        TYPE_BOOL, TYPE_UINT16, TYPE_HEX32, TYPE_STRING, TYPE_OTHERS
    };

    struct UserVarItem {
        string name;
        bool required;
        UserVarType type;
    };

    map<string, vector<UserVarItem>> var_table{
            {"client",
                      {
                              {"CLIENT_RANDOM_NONCE",  false, TYPE_BOOL},
                              {"CLIENT_USE_PLATFORM_SERVICES", false, TYPE_BOOL},
                      }
            },
            {
             "service_provider",
                      {
                              {"QUERY_IAS_PRODUCTION", false, TYPE_BOOL},
                              {"SPID",                         false,  TYPE_HEX32},
                              {"QUOTE_TYPE",         false, TYPE_UINT16},
                              {"IAS_PRIMARY_SUBSCRIPTION_KEY", false,  TYPE_HEX32},
                              {"IAS_SECONDARY_SUBSCRIPTION_KEY",    false,  TYPE_HEX32},
                      }
            },
            {
             "trust_policy",
                      {
                              {"POLICY_MRSIGNER",      false,  TYPE_OTHERS},
                              {"POLICY_MRENCLAVE",      false,  TYPE_OTHERS},
                              {"POLICY_PRODUCT_ID",            false,  TYPE_UINT16},
                              {"POLICY_ISV_MIN_SVN", false, TYPE_UINT16},
                              {"POLICY_ALLOW_DEBUG",           false, TYPE_BOOL},
                              {"POLICY_ALLOW_CONFIGURATION_NEEDED", false, TYPE_BOOL},
                      }
            },
            {
             "debug", {
                              {"VERBOSE",              false, TYPE_BOOL},
                              {"DEBUG",                        false, TYPE_BOOL},
                      }
            }
    };

    for (const auto &category:var_table) {
        auto toml_category = toml_config->get_table(category.first);

        for (const auto &var_def: category.second) {

            if (toml_category->contains(var_def.name)) {
                switch (var_def.type) {
                    case TYPE_BOOL: {
                        auto val = toml_category->get_as<bool>(var_def.name);
                        numeric_map.insert({var_def.name, *val});
                        break;
                    }
                    case TYPE_UINT16: {
                        auto val = toml_category->get_as<uint16_t>(var_def.name);
                        numeric_map.insert({var_def.name, *val});
                        break;
                    }
                    case TYPE_HEX32: {
                        auto val = toml_category->get_as<string>(var_def.name);
                        h32_map.insert({var_def.name, check_hstr<32>(*val)});
                        break;
                    }
                    case TYPE_STRING: {
                        auto val = toml_category->get_as<string>(var_def.name);
                        str_map.insert({var_def.name, *val});
                        break;
                    }
                    case TYPE_OTHERS:
                        if (var_def.name == "POLICY_MRSIGNER") {
                            auto val = toml_category->get_as<string>(var_def.name);
                            hex::decode(&POLICY_MRSIGNER[0], POLICY_MRSIGNER.size(), *val);
                        }else if (var_def.name == "POLICY_MRENCLAVE") {
                            auto val = toml_category->get_as<string>(var_def.name);
                            hex::decode(&POLICY_MRENCLAVE[0], POLICY_MRENCLAVE.size(), *val);
                        } else {
                            cerr << "Unexpected parameter: " << var_def.name << " in " << category.first << endl;
                            exit(EXIT_FAILURE);
                        }
                }
            } else {
                if (var_def.required) {
                    cerr << "Cannot find required parameter: " << var_def.name << " in " << category.first << endl;
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
}

int UserArgs::parse_int(const string &str) {
    return stoi(str, nullptr, 0);
}

template<size_t CharLength>
array<char, CharLength> UserArgs::check_hstr(const string &hex_str) {
    if (hex_str.length() != CharLength) {
        cerr << "Hex string length doesn't match: " << hex_str.length() << endl;
        exit(EXIT_FAILURE);
    }

    array<char, CharLength> output{};
    for (size_t i = 0; i < CharLength; i++) {
        if (!isxdigit(hex_str[i])) {
            cerr << "Invalid hex digit: " << unsigned(hex_str[i]) << hex_str[i] << endl;
            exit(EXIT_FAILURE);
        } else {
            output[i] = hex_str[i];
        }
    }

    return output;
}

template<class T>
T UserArgs::search_numeric(const string &name, T default_value) const {
    auto iter = numeric_map.find(name);
    if (iter == numeric_map.end()) {
        return default_value;
    } else {
        return iter->second;
    }
}

template<class T>
T UserArgs::search_numeric(const string &name) const {
    auto iter = numeric_map.find(name);
    if (iter == numeric_map.end()) {
        exit(EXIT_FAILURE);
    } else {
        return iter->second;
    }
}


bool UserArgs::get_query_ias_production() const {
    // [0, 1] [DEFAULT = 0]
    return search_numeric("QUERY_IAS_DEVELOPMENT", false);
}

sgx_spid_t UserArgs::get_spid() const {
    // [hex[32]]
    auto iter = h32_map.find("SPID");
    if (iter == h32_map.end()) {
        exit(EXIT_FAILURE);
    } else {
        sgx_spid_t spid = sgx_spid_t();
        hex::decode((char *) spid.id, sizeof(sgx_spid_t), iter->second);
        return spid;
    }
}

sgx_quote_sign_type_t UserArgs::get_quote_type() const {
    // [uint16] [DEFAULT = 0]
    if (search_numeric("QUOTE_TYPE", 0) == 0) {
        return sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;
    } else {
        return sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
    }
}

bool UserArgs::get_client_random_nonce() const {
    // [0, 1] [DEFAULT = 1]
    return search_numeric("CLIENT_RANDOM_NONCE", 1);
}

bool UserArgs::get_client_use_platform_services() const {
    // [0, 1] [DEFAULT = 0]
    return search_numeric("CLIENT_USE_PLATFORM_SERVICES", 0);
}

array<char, 32> UserArgs::get_ias_primary_subscription_key() const {
    // [hex[32]]
    auto iter = h32_map.find("IAS_PRIMARY_SUBSCRIPTION_KEY");
    if (iter == h32_map.end()) {
        exit(EXIT_FAILURE);
    } else {
        return iter->second;
    }
}

array<char, 32> UserArgs::get_ias_secondary_subscription_key() const {
    // [hex[32]]
    auto iter = h32_map.find("IAS_SECONDARY_SUBSCRIPTION_KEY");
    if (iter == h32_map.end()) {
        exit(EXIT_FAILURE);
    } else {
        return iter->second;
    }
}

array<uint8_t, 32> UserArgs::get_policy_mrsigner() const {
    // [hex[64]]
    return POLICY_MRSIGNER;
}

array<uint8_t, 32> UserArgs::get_policy_mrenclave() const {
    // [hex[64]]
    return POLICY_MRENCLAVE;
}

uint16_t UserArgs::get_policy_product_id() const {
    // [uint16] [REQUIRED]
    return search_numeric<uint16_t>("POLICY_PRODUCT_ID");
}

uint16_t UserArgs::get_policy_isv_min_svn() const {
    // [uint16] [DEFAULT = 0]
    return search_numeric<uint16_t>("POLICY_ISV_MIN_SVN", 0);
}

bool UserArgs::get_policy_allow_debug() const {
    // [0, 1] [DEFAULT = 0]
    return search_numeric<uint16_t>("POLICY_ALLOW_DEBUG", false);
}

bool UserArgs::get_policy_allow_configuration_needed() const {
    // [0, 1] [DEFAULT = 0]
    return search_numeric<uint16_t>("POLICY_ALLOW_CONFIGURATION_NEEDED", false);
}

bool UserArgs::get_sgx_verbose() const {
    // [0, 1] [DEFAULT = 0]
    return search_numeric<uint16_t>("VERBOSE", false);
}

bool UserArgs::get_sgx_debug() const {
    // [0, 1] [DEFAULT = 0]
    return search_numeric<uint16_t>("DEBUG", false);
}

//ra_trust_policy UserArgs::get_trust_policy() const {
//    ra_trust_policy policy;
//
//    policy.allow_debug = get_policy_allow_debug();
//    policy.allow_configuration_needed = get_policy_allow_configuration_needed();
//    policy.isv_product_id = get_policy_product_id();
//    policy.isv_min_svn = get_policy_isv_min_svn();
//    memcpy(&policy.mrsigner, get_policy_mrsigner().data(), sizeof(sgx_measurement_t));
//
//    return policy;
//}
