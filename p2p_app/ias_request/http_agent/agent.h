/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef SGX_EML_AGENT_H
#define SGX_EML_AGENT_H


#include <string>
#include <map>
#include "../httpparser/response.h"

using namespace httpparser;
using namespace std;

class Agent {
public:
    virtual ~Agent() = default;

    virtual string GET(const string &url, const map<string, string> &header, Response &resp) = 0;

    virtual string POST(const string &url, const map<string, string> &header, const string &body, Response &resp) = 0;
};


#endif //SGX_EML_AGENT_H
