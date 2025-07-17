#pragma once

#include <cstdint>
#include "directionalField.hpp"
#include "tcpFlags.hpp"

namespace ipxp
{

struct Packet {
    uint8_t ipTtl;
    uint8_t ipFlags;
    uint16_t ipLength;
    uint16_t tcpWindow;
    uint64_t tcpOptions;
    uint32_t tcpMss;
    TcpFlags tcpFlags;
};

} // namespace ipxp
