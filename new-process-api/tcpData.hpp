#pragma once

#include <cstdint>

#include "tcpFlags.hpp"

namespace ipxp
{

struct TCPData {
    uint16_t window{0};
    uint64_t options{0};
    uint32_t mss{0};
    TCPFlags flags{};
    uint32_t sequence{0};
    uint32_t acknowledgment{0};
};

} // namespace ipxp


