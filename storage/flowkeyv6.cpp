/**
 * \file flowkeyv6.cpp
 * \brief FlowKey class specialization for ipv6
 */
/*
 * Copyright (C) 2023 CESNET
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
 */

#include "flowkeyv6.hpp"
#include "flowkey.tpp"
#include <cstring>

namespace ipxp {
FlowKeyV6& FlowKeyV6::operator=(const Packet& pkt) noexcept
{
    FlowKey::operator=(pkt);
    ip_version = IP::v6;
    memcpy(src_ip.data(), pkt.src_ip.v6, 16);
    memcpy(dst_ip.data(), pkt.dst_ip.v6, 16);
    return *this;
}

FlowKeyV6& FlowKeyV6::save_reversed(const Packet& pkt) noexcept
{
    FlowKey::save_reversed(pkt);
    ip_version = IP::v6;
    memcpy(src_ip.data(), pkt.dst_ip.v6, 16);
    memcpy(dst_ip.data(), pkt.src_ip.v6, 16);
    return *this;
}

FlowKeyV6& FlowKeyV6::save_sorted(const Packet& pkt) noexcept
{
    if ( [](const uint8_t* addr1,const  uint8_t* addr2)->int8_t {
            for (auto i = 0; i < 16 ; i++)
                if (addr1[15-i] != addr2[15-i])
                    return (int8_t)(addr1[15-i] - addr2[15-i]);
            return 0;
    }(pkt.src_ip.v6,pkt.dst_ip.v6) < 0 )
        *this = pkt;
    else
        this->save_reversed(pkt);
    return *this;
}
} // namespace ipxp