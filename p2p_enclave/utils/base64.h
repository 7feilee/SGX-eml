#ifndef __BASE64_H
#define __BASE64_H

#include <string>
#include <vector>

//std::string base64_encode(const std::vector<uint8_t> &msg);

std::vector<uint8_t> base64_decode(const std::string &msg);

#endif

