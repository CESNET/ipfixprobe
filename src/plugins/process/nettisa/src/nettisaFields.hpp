/**
 * @file
 * @brief Export fields of nettisa plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::nettisa {

/**
 * @enum NetTimeSeriesFields
 * @brief Enumerates the fields exported by the NetTimeSeries plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
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

} // namespace ipxp::process::nettisa
