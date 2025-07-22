#pragma once

#include <cstdint>
#include <sys/time.h>

#include "directionalField.hpp"
#include "tcpFlags.hpp"

namespace ipxp
{

struct Packet {
    timeval timestamp;
    uint8_t ipTtl;
    uint8_t ipFlags;
    uint16_t ipLength;
    uint16_t tcpWindow;
    uint64_t tcpOptions;
    uint32_t tcpMss;
    TcpFlags tcpFlags;

    uint32_t realLength;
    uint32_t receivedLength;

    Direction direction;

};

} // namespace ipxp
