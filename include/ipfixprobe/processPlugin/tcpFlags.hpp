#pragma once

#include <cstdint>

namespace ipxp {

/**
 * @struct TCPFlags
 * @brief Structure representing TCP flags.
 */
union TCPFlags {

    constexpr TCPFlags() noexcept
    : raw(0) {}

    constexpr TCPFlags(const uint8_t raw) noexcept
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

    uint8_t raw; ///< Byte representing TCP flags

    constexpr
    TCPFlags operator|(const TCPFlags& other) const noexcept
    {
        TCPFlags result;
        result.raw = raw | other.raw;
        return result;
    }

    constexpr
    TCPFlags operator&(const TCPFlags& other) const noexcept
    {
        TCPFlags result;
        result.raw = raw & other.raw;
        return result;
    }

    constexpr
    TCPFlags& operator|=(const TCPFlags& other) noexcept
    {
        raw |= other.raw;
        return *this;
    }

    constexpr
    TCPFlags& operator&=(const TCPFlags& other) noexcept
    {
        raw &= other.raw;
        return *this;
    }

    constexpr
    bool operator==(const TCPFlags& other) const noexcept
    {
        return raw == other.raw;
    }

    constexpr operator uint8_t() const noexcept
    {
        return raw;
    }
};

static_assert(sizeof(TCPFlags) != sizeof(uint8_t), "Invalid TCPFlags size");

} // namespace ipxp