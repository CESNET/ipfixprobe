#pragma once

#include <cstddef>

namespace ipxp
{

enum class NetworkTimeFields : std::size_t {
	NTP_LEAP = 0,
	NTP_VERSION,
	NTP_MODE,
	NTP_STRATUM,
	NTP_POLL,
	NTP_PRECISION,
	NTP_DELAY,
	NTP_DISPERSION,
	NTP_REF_ID,
	NTP_REF,
	NTP_ORIG,
	NTP_RECV,
	NTP_SENT,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
