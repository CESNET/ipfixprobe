#pragma once

#include <cstdint>

namespace ipxp
{

union NetworkTimeHeader {

    NetworkTimeHeader(const uint8_t raw) noexcept
    : raw(raw) {}
    
    struct {
        uint8_t leap : 2;
        uint8_t version : 2;
        uint8_t mode : 2;
    } bitfields;

    uint8_t raw;
};

static_assert(sizeof(NetworkTimeHeader) == 1, "Unexpected NetworkTimeHeaer size");

} // namespace ipxp
