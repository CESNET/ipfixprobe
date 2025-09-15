#pragma once

#include <cstddef>

namespace ipxp
{

enum class SSDPFields : std::size_t {
	SSDP_LOCATION_PORT = 0,
	SSDP_NT,
	SSDP_SERVER,
	SSDP_ST,
	SSDP_USER_AGENT,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
