#pragma once

#include <cstdint>

#include "tlsVersion.hpp"

namespace ipxp::tls
{

struct ExtensionSNIHeader {
	uint8_t type;
	uint16_t length;
	/* Hostname bytes... */
} __attribute__((packed));

static_assert(sizeof(ExtensionSNIHeader) == 3, 
	"Invalid ExtensionSNIHeader size");

} // namespace ipxp::tls
