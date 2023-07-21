/**
 * \file utils.cpp
 * \brief Utility functions source
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *
 *
 */

#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <utility>

#include <ipfixprobe/utils.hpp>

namespace ipxp {

void parse_range(
    const std::string& arg,
    std::string& from,
    std::string& to,
    const std::string& delim)
{
    size_t pos = arg.find(delim);
    if (pos == std::string::npos) {
        throw std::invalid_argument(arg);
    }

    if (delim.find("-") != std::string::npos) {
        size_t tmp = arg.find_first_not_of(" \t\r\n");
        if (arg[tmp] == '-') {
            tmp = arg.find(delim, pos + 1);
            if (tmp != std::string::npos) {
                pos = tmp;
            }
        }
    }

    from = arg.substr(0, pos);
    to = arg.substr(pos + 1);
    trim_str(from);
    trim_str(to);
}

bool str2bool(std::string str)
{
    std::set<std::string> accepted_values = {"y", "yes", "t", "true", "on", "1"};
    trim_str(str);
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return accepted_values.find(str) != accepted_values.end();
}

void trim_str(std::string& str)
{
    // when std::string::npos returned by find
    // string.erase() will remove all characters till end
    // https://cplusplus.com/reference/string/string/erase/
    if (str.length() > 0) {
        str.erase(0, str.find_first_not_of(" \t\n\r"));
        size_t pos = str.find_last_not_of(" \t\n\r");
        if (pos != std::string::npos) {
            str.erase(str.find_last_not_of(" \t\n\r") + 1);
        }
    }
}

void phton64(uint8_t* p, uint64_t v)
{
    int shift = 56;

    for (unsigned int i = 0; i < 8; i++) {
        p[i] = (uint8_t) (v >> (shift - (i * 8)));
    }
}

uint64_t pntoh64(const void* p)
{
    uint64_t buffer = 0;
    int shift = 56;

    for (unsigned x = 0; x < 8; x++) {
        buffer |= (uint64_t) * ((const uint8_t*) (p) + x) << (shift - (x * 8));
    }
    return buffer;
}

uint32_t htonf(float value)
{
    union castHelper {
        uint32_t uint32;
        float float32;
    } helper;

    static_assert(sizeof(uint32_t) == sizeof(float), "sizeof(uint32_t) != sizeof(float)");

    helper.float32 = value;
    return htonl(helper.uint32);
}

uint32_t variable2ipfix_buffer(uint8_t* buffer2write, uint8_t* buffer2read, uint16_t len)
{
    uint32_t ptr = 0;
    if (len >= 255) {
        buffer2write[ptr++] = 255;
        *(uint16_t*) (buffer2write + ptr) = htons(len);
        ptr += sizeof(uint16_t);
    } else {
        buffer2write[ptr++] = len;
    }
    std::memcpy(buffer2write + ptr, buffer2read, len);
    return ptr + len;
}

uint64_t timeval2usec(const struct timeval& tv)
{
   constexpr size_t usec_in_sec = 1000000;
   return tv.tv_sec * usec_in_sec + tv.tv_usec;
}

} // namespace ipxp