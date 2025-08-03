#pragma once

#include <cstddef>

namespace ipxp
{

enum class PacketHistogramFields : std::size_t {
	S_PHISTS_SIZES = 0,
	S_PHISTS_IPT,
	D_PHISTS_SIZES,
	D_PHISTS_IPT,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
