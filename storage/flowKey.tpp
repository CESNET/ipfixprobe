#pragma once

#include <cstdint>
#include <cstddef>
#include <array>

namespace ipxp {

template <size_t IPSize>
struct FlowKey {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t ip_version;
    std::array<uint8_t, IPSize> src_ip;
    std::array<uint8_t, IPSize> dst_ip;
    uint16_t vlan_id;
} __attribute__((packed));

using FlowKeyv4 = FlowKey<4>;
using FlowKeyv6 = FlowKey<16>;

} // namespace ipxp