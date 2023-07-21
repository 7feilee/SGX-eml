#ifndef SGX_EML_IAS_REQUEST_H
#define SGX_EML_IAS_REQUEST_H

#include <string>
#include <exception>
#include "http_agent/agent.h"
#include "HttpStatusCodes_C++11.h"
#include <cppcodec/cppcodec/base64_default_rfc4648.hpp>
#include <json.hpp>

using namespace std;
using namespace HttpStatus;
//
//#define HTTP_OK                    200
//#define HTTP_BADREQUEST            400
//#define HTTP_UNAUTHORIZED        401
//#define HTTP_NOT_FOUND            404
//#define HTTP_SERVER_ERR            500
//#define HTTP_UNAVAILABLE        503

class ias_http_exception : public exception {
    unsigned code;
    string info;
public:
    ias_http_exception(const string &where, unsigned code) : code(code) {
        info = where + " " + reasonPhrase(code);
    }

    unsigned status_code() {
        return code;
    }

    const char *what() const noexcept override {
        return info.c_str();
    }
};

enum Attestation_Evidence_Payload {
    isvEnclaveQuote,
    pseManifest,
    nonce,
};

class IAS_Request {
    typedef array<char, 32> subkey_t;
    string key_header;
    string base_url;
    array<string, 2> subscription_key;

public:
    IAS_Request(const subkey_t &primary_key, const subkey_t &secondary_key, bool production)
            : subscription_key() {
        static const string ias_servers[2] = {
                "https://api.trustedservices.intel.com/sgx/dev",
                "https://api.trustedservices.intel.com/sgx"
        };
        key_header = "Ocp-Apim-Subscription-Key";
        base_url = production ? ias_servers[1] : ias_servers[0];
        subscription_key[0].assign(primary_key.begin(), primary_key.end());
        subscription_key[1].assign(secondary_key.begin(), secondary_key.end());
    }

    string sigrl(Agent *agent, uint32_t group_id, Response &response) {
        const static string api_url = base_url + "/attestation/v4/sigrl/";

        /* generate url */
        char gid[9];
        sprintf(gid, "%08x", group_id);
        string url = api_url + gid;

        /* request */
        int key_index = 0;
        do {
            map<string, string> header;
            header.insert(make_pair(key_header, subscription_key[key_index]));
            agent->GET(url, header, response);
            key_index++;
        } while (response.statusCode == 401 && key_index < 2);

        if (response.statusCode != 200) {
            throw ias_http_exception(url, response.statusCode);
        }

        return response.content_string();
    }

    string report(Agent *agent, map<Attestation_Evidence_Payload, vector<uint8_t >> &payload, Response &response) {
        const static string api_url = base_url + "/attestation/v4/report";

        /* build post body */
//        string body = "{";
        string body = "";
        json::JSON json;


        auto isvEnclaveQuote = payload.find(Attestation_Evidence_Payload::isvEnclaveQuote);
        if (isvEnclaveQuote == payload.end()) {
            throw invalid_argument("isvEnclaveQuote");
        }
        json["isvEnclaveQuote"] = base64::encode(isvEnclaveQuote->second);
//        body.append("\"isvEnclaveQuote\": ").append("\"").append(base64::encode(isvEnclaveQuote->second)).append("\"");

        auto pseManifest = payload.find(Attestation_Evidence_Payload::pseManifest);
        if (pseManifest != payload.end()) {
            if (pseManifest->second.size() != 256) {
                throw invalid_argument("pseManifest");
            }
            json["pseManifest"] = base64::encode(pseManifest->second);
//            body.append(", ").append("\"pseManifest\": ").append("\"").append(base64::encode(pseManifest->second)).append("\"");
        }

        auto nonce = payload.find(Attestation_Evidence_Payload::nonce);
        if (nonce != payload.end()) {
            if (nonce->second.size() > 32) {
                throw invalid_argument("nonce");
            }
            json["nonce"] = string(nonce->second.begin(), nonce->second.end());
        }

        /* request */
        string resp;
        int key_index = 0;
        do {
            map<string, string> header;
            header.insert({key_header, subscription_key[key_index]});
            header.insert({"Content-Type", "application/json"});
            resp = agent->POST(api_url, header, json.dump(), response);
            key_index++;
        } while (response.statusCode == 400 && key_index < 2);

        if (response.statusCode != 200) {
            throw ias_http_exception(api_url, response.statusCode);
        }

        return resp;
    }


};

#endif //SGX_EML_IAS_REQUEST_H
