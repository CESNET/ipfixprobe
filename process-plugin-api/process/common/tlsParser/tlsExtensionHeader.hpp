#pragma once

#include <cstdint>

#include "tlsExtensionType.hpp"

namespace ipxp::tls
{
    
struct ExtensionHeader {
    TLSExtensionType type;
	uint16_t length;
	/* Extension specific data... */
} __attribute__((packed));

static_assert(sizeof(ExtensionHeader) == 4, "Invalid ExtensionHeader size");

} // namespace ipxp::tls
