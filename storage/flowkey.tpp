/**
 * \file flowkey.cpp
 * \brief FlowKey class contains key attributes of flow used for creating hash
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

#include "flowkey.hpp"

namespace ipxp {
template<uint16_t IPSize>
FlowKey<IPSize>& FlowKey<IPSize>::operator=(const Packet& pkt) noexcept
{
    proto = pkt.ip_proto;
    src_port = pkt.src_port;
    dst_port = pkt.dst_port;
    vlan_id = pkt.vlan_id;
    swapped = false;
    return *this;
}

/**
 * @brief Create reverse key of flow.
 * @param pkt Incoming packet.
 */
template<uint16_t IPSize>
FlowKey<IPSize>& FlowKey<IPSize>::save_reversed(const Packet& pkt) noexcept
{
    *this = pkt;
    src_port = pkt.dst_port;
    dst_port = pkt.src_port;
    swapped = true;
    return *this;
}
} // namespace ipxp