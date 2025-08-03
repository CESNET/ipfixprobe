#pragma once

#include <cstdint>

namespace ipxp
{


union TLSVersion {
	uint16_t version;

	struct {
		uint8_t major;
		uint8_t minor;
	} bytes;
	
} __attribute__((packed));

static_assert(sizeof(TLSVersion) == 2, "Invalid TLSVersion size");

} // namespace ipxp
