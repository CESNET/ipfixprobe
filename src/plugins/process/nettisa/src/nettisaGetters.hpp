/**
 * @file nettisaGetters.hpp
 * @brief Getters for NetTISA plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "nettisaContext.hpp"

namespace ipxp::process::nettisa {

inline constexpr const NetTimeSeriesContext& asNetTimeSeriesContext(const void* context) noexcept
{
	return *static_cast<const NetTimeSeriesContext*>(context);
}

// NetTimeSeriesField::NTS_MEAN
inline constexpr auto getNTSMeanField
	= [](const void* context) { return asNetTimeSeriesContext(context).mean; };

// NetTimeSeriesField::NTS_MIN
inline constexpr auto getNTSMinField
	= [](const void* context) { return asNetTimeSeriesContext(context).min; };

// NetTimeSeriesField::NTS_MAX
inline constexpr auto getNTSMaxField
	= [](const void* context) { return asNetTimeSeriesContext(context).max; };

// NetTimeSeriesField::NTS_STDEV
inline constexpr auto getNTSStdevField
	= [](const void* context) { return asNetTimeSeriesContext(context).standardDeviation; };

// NetTimeSeriesField::NTS_KURTOSIS
inline constexpr auto getNTSKurtosisField
	= [](const void* context) { return asNetTimeSeriesContext(context).kurtosis; };

// NetTimeSeriesField::NTS_ROOT_MEAN_SQUARE
inline constexpr auto getNTSRootMeanSquareField
	= [](const void* context) { return asNetTimeSeriesContext(context).rootMeanSquare; };

// NetTimeSeriesField::NTS_AVERAGE_DISPERSION
inline constexpr auto getNTSAverageDispersionField
	= [](const void* context) { return asNetTimeSeriesContext(context).averageDispersion; };

// NetTimeSeriesField::NTS_MEAN_SCALED_TIME
inline constexpr auto getNTSMeanScaledTimeField
	= [](const void* context) { return asNetTimeSeriesContext(context).meanScaledTime; };

// NetTimeSeriesField::NTS_MEAN_DIFFTIMES
inline constexpr auto getNTSMeanDifftimesField
	= [](const void* context) { return asNetTimeSeriesContext(context).meanDifftimes; };

// NetTimeSeriesField::NTS_MIN_DIFFTIMES
inline constexpr auto getNTSMinDifftimesField
	= [](const void* context) { return asNetTimeSeriesContext(context).minDifftimes; };

// NetTimeSeriesField::NTS_MAX_DIFFTIMES
inline constexpr auto getNTSMaxDifftimesField
	= [](const void* context) { return asNetTimeSeriesContext(context).maxDifftimes; };

// NetTimeSeriesField::NTS_TIME_DISTRIBUTION
inline constexpr auto getNTSTimeDistributionField
	= [](const void* context) { return asNetTimeSeriesContext(context).timeDistribution; };

// NetTimeSeriesField::NTS_SWITCHING_RATIO
inline constexpr auto getNTSSwitchingRatioField
	= [](const void* context) { return asNetTimeSeriesContext(context).switchingRatio; };

} // namespace ipxp::process::nettisa
