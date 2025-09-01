#pragma once

#include <cstddef>

namespace ipxp
{

enum class NetTimeSeriesFields : std::size_t {
	NTS_MEAN = 0,
	NTS_MIN,
	NTS_MAX,
	NTS_STDEV,
	NTS_KURTOSIS,
	NTS_ROOT_MEAN_SQUARE,
	NTS_AVERAGE_DISPERSION,                                                                         
	NTS_MEAN_SCALED_TIME,
	NTS_MEAN_DIFFTIMES,
	NTS_MIN_DIFFTIMES,
	NTS_MAX_DIFFTIMES,
	NTS_TIME_DISTRIBUTION,                                                                                
	NTS_SWITCHING_RATIO,
	FIELDS_SIZE
};    
    
} // namespace ipxp
