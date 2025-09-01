#pragma once

#include <cstddef>

namespace ipxp
{

enum class PassiveDNSFields : std::size_t {
	DNS_ID = 0,
	DNS_ATYPE,
	DNS_NAME,
	DNS_RR_TTL,
	DNS_IP,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
