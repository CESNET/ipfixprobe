#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <optional>

#include "quicVersion.hpp"

namespace ipxp
{
    
class QUICHeaderView {
public:
    constexpr static std::size_t MIN_HEADER_SIZE = 7;
    constexpr static std::size_t QUIC_MIN_PACKET_LENGTH = 8;

    enum class PacketType {
        INITIAL = 0,
        ZERO_RTT,
        HANDSHAKE,
        RETRY,
        VERSION_NEGOTIATION = 7
    };

    std::byte headerForm;
    std::optional<QUICVersion> version;
    //uint8_t destConnectionIdLength;
    std::span<const uint8_t> destinationConnectionId;
    //uint8_t srcConnectionIdLength;
    std::span<const uint8_t> sourceConnectionId;


    constexpr static std::optional<QUICHeaderView> createFrom(
        std::span<const std::byte> payload, 
        const uint8_t l4Protocol
    ) noexcept;

    constexpr std::size_t getLength() const noexcept;

    constexpr PacketType getPacketType() const noexcept;

private:
};


} // namespace ipxp
