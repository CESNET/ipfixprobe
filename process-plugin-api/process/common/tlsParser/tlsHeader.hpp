#pragma once

#include <cstdint>

namespace ipxp::tls
{

struct Header {
    uint8_t type;
	Version version;
	uint16_t length;
	/* Record data... */

    enum class Type : uint8_t {
        HANDSHAKE = 22
    };

} __attribute__((packed));


} // namespace ipxp::tls
