#pragma once

#include <cstdint>

#include "tlsVersion.hpp"

namespace ipxp::tls
{

struct HandshakeHeader {
	constexpr static uint16_t TYPE = 22;

	uint8_t type;
	uint8_t length1; // length field is 3 bytes long...
	uint16_t length2;
	Version version;

	enum class Type : uint8_t {
        CLIENT_HELLO = 1,
		SERVER_HELLO = 2
    };

	/* Handshake data... */
} __attribute__((packed));


} // namespace ipxp
