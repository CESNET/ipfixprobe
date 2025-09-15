#pragma once

#include <cstdint>

#include "tlsVersion.hpp"

namespace ipxp
{

struct TLSHandshake {
	enum class Type : uint8_t {
        CLIENT_HELLO = 1,
		SERVER_HELLO = 2
    };

	Type type;
	uint8_t length1; // length field is 3 bytes long...
	uint16_t length2;
	TLSVersion version;

	/* Handshake data... */
} __attribute__((packed));


} // namespace ipxp
