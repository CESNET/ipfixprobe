#pragma once

#include <cstddef>

namespace ipxp
{

enum class DNSSDFields : std::size_t {
	DNSSD_QUERIES = 0,
	DNSSD_RESPONSES,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
