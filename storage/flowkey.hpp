/**
 * \file flowkey.hpp
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

#ifndef IPFIXPROBE_CACHE_FLOW_KEY_H
#define IPFIXPROBE_CACHE_FLOW_KEY_H

#include <array>
#include <cstdint>
#include <ipfixprobe/packet.hpp>
#include <string>

namespace ipxp {

template<uint16_t IPSize>
struct __attribute__((packed)) FlowKey {
    uint16_t src_port; ///< Source port.
    uint16_t dst_port; ///< Destination port.
    uint8_t proto; ///< ID of next level protocol.
    uint8_t ip_version; ///< ip4 or ip6.
    std::array<uint8_t, IPSize> src_ip; ///< Source ip
    std::array<uint8_t, IPSize> dst_ip; ///< Destination ip
    uint16_t vlan_id;
    bool swapped;
    FlowKey<IPSize>& operator=(const Packet& pkt) noexcept;
    FlowKey<IPSize>& save_reversed(const Packet& pkt) noexcept;
};

} // namespace ipxp
#endif // IPFIXPROBE_CACHE_FLOW_KEY_H
