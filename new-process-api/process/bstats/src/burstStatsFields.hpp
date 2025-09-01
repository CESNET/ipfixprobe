#pragma once

#include <cstddef>

namespace ipxp
{

enum class BurstStatsFields : std::size_t {
	SBI_BRST_PACKETS = 0,
	SBI_BRST_BYTES,
	SBI_BRST_TIME_START,
	SBI_BRST_TIME_STOP,
    DBI_BRST_PACKETS,
	DBI_BRST_BYTES,
	DBI_BRST_TIME_START,
	DBI_BRST_TIME_STOP,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
