#pragma once

#include <cstddef>

namespace ipxp
{

enum class ICMPFields : std::size_t {
	L4_ICMP_TYPE_CODE = 0,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
