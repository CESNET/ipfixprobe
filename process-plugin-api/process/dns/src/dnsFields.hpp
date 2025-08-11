#pragma once

#include <cstddef>

namespace ipxp
{

enum class DNSFields : std::size_t {
	DNS_ID = 0,
	DNS_ANSWERS,
	DNS_RCODE,
	DNS_NAME,
	DNS_QTYPE,
	DNS_CLASS,
	DNS_RR_TTL,
	DNS_RLENGTH,
	DNS_RDATA,
	DNS_PSIZE,
	DNS_DO,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
