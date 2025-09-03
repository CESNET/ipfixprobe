#pragma once

#include <cstdint>

namespace ipxp {

/**
 * @struct TcpFlags
 * @brief Structure representing TCP flags.
 */
union TcpFlags {

    constexpr TcpFlags() noexcept
    : raw(std::byte{0}) {}

    constexpr TcpFlags(std::byte raw) noexcept
    : raw(raw) {}

    struct {
        uint8_t noOperation : 1;              ///< 0: No-Operation (NS) flag
        uint8_t congestionWindowReduced : 1;  ///< 1: Congestion Window Reduced (CWR) flag
        uint8_t ecnEcho : 1;                  ///< 2: ECN-Echo (ECE) flag
        uint8_t urgent : 1;                   ///< 3: Urgent (URG) flag
        uint8_t acknowledgment : 1;           ///< 4: Acknowledgment (ACK) flag
        uint8_t push : 1;                     ///< 5: Push (PSH) flag
        uint8_t reset : 1;                    ///< 6: Reset (RST) flag
        uint8_t synchronize : 1;              ///< 7: Synchronize (SYN) flag
        uint8_t finish : 1;                   ///< 8: Finish (FIN) flag
    } bitfields;

    std::byte raw; ///< Byte representing TCP flags

    constexpr
    TcpFlags operator|(const TcpFlags& other) const noexcept
    {
        TcpFlags result;
        result.raw = this->raw | other.raw;
        return result;
    }

    constexpr
    TcpFlags operator&(const TcpFlags& other) const noexcept
    {
        TcpFlags result;
        result.raw = raw & other.raw;
        return result;
    }

    constexpr
    TcpFlags& operator|=(const TcpFlags& other) noexcept
    {
        raw |= other.raw;
        return *this;
    }

    constexpr
    TcpFlags& operator&=(const TcpFlags& other) noexcept
    {
        raw &= other.raw;
        return *this;
    }

    constexpr
    bool operator==(const TcpFlags& other) const noexcept
    {
        return raw == other.raw;
    }

    constexpr operator std::byte() const noexcept
    {
        return raw;
    }
};

static_assert(sizeof(TcpFlags) != sizeof(std::byte), "Invalid TcpFlags size");

} // namespace ipxp