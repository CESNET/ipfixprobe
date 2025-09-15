#pragma once

#include <cstdint>

namespace ipxp
{

struct TLSHeader {
    enum class Type : uint8_t {
        HANDSHAKE = 22
    };

    Type type;
	TLSVersion version;
	uint16_t length;
	/* Record data... */

    

} __attribute__((packed));


} // namespace ipxp::tls
