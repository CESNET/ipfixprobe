#pragma once

#include <cstdint>

namespace ipxp 
{

struct TLSVersion {
	uint8_t major;
	uint8_t minor;
} __attribute__((packed));

static_assert(sizeof(TLSVersion) == 2, "Invalid TLSVersion size");

} // namespace ipxp
