/**
 * \file flowkeyv4.cpp
 * \brief FlowKey class specialization for ipv4
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

#include "flowkeyv4.hpp"
#include "flowkey.tpp"
#include <cstring>

namespace ipxp {
FlowKeyV4& FlowKeyV4::operator=(const Packet& pkt) noexcept
{
    FlowKey::operator=(pkt);
    ip_version = IP::v4;
    memcpy(src_ip.data(), &pkt.src_ip.v4, sizeof(pkt.src_ip.v4));
    memcpy(dst_ip.data(), &pkt.dst_ip.v4, sizeof(pkt.dst_ip.v4));
    return *this;
}

FlowKeyV4& FlowKeyV4::save_reversed(const Packet& pkt) noexcept
{
    FlowKey::save_reversed(pkt);
    ip_version = IP::v4;
    memcpy(src_ip.data(), &pkt.dst_ip.v4, sizeof(pkt.dst_ip.v4));
    memcpy(dst_ip.data(), &pkt.src_ip.v4, sizeof(pkt.src_ip.v4));
    return *this;
}

FlowKeyV4& FlowKeyV4::save_sorted(const Packet& pkt) noexcept
{
    if ( pkt.src_ip.v4 < pkt.dst_ip.v4)
        *this = pkt;
    else
        this->save_reversed(pkt);
    return *this;
}
} // namespace ipxp