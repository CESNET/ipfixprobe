#pragma once

#include <cstdint>
#include <sys/time.h>
#include <span>
#include <optional>

#include "directionalField.hpp"
#include "tcpData.hpp"
#include "flowKey.hpp"

namespace ipxp
{

struct Packet {
    FlowKey flowKey{};

    uint64_t timestamp{0};
    uint8_t ipTTL{0};
    uint8_t ipFlags{0};
    uint16_t ipLength{0};

    std::optional<TCPData> tcpData{std::nullopt};

    uint32_t realLength{0};
    //uint32_t receivedLength{0};

    Direction direction{Direction::Forward};

    std::span<const std::byte> payload;   
    std::optional<uint32_t> mplsTopLabel;
    std::optional<uint16_t> vlanId;

};

struct PacketFeatures {};

} // namespace ipxp