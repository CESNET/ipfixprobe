#pragma once

#include <cstdint>

namespace ipxp {

/**
 * @struct TcpFlags
 * @brief Structure representing TCP flags.
 */
union TcpFlags {
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
    } flags;

    uint8_t raw; ///< Byte representing TCP flags
};

static_assert(sizeof(TcpFlags) != sizeof(uint8_t), "Invalid TcpFlags size");

} // namespace ipxp