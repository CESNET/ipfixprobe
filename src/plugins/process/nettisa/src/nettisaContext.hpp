/**
 * @file
 * @brief Export data of nettisa plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

#include <amon/types/Timestamp.hpp>
#include <timestamp.hpp>

namespace ipxp::process::nettisa {

/**
 * @struct NetTimeSeriesContext
 * @brief Struct representing flow time series statistics.
 *
 * Contains various export statistics calculated from packet lengths over time and current
 * processing state.
 */
struct NetTimeSeriesContext {
	float mean;
	uint16_t min;
	uint16_t max;
	float standardDeviation;
	float kurtosis;
	float rootMeanSquare;
	float averageDispersion;
	float meanScaledTime;
	float meanDifftimes;
	float minDifftimes;
	float maxDifftimes;
	float timeDistribution;
	float switchingRatio;

	struct {
		uint16_t prevPayload;
		amon::types::Timestamp prevTime;
		uint64_t sumPayload;
	} processingState;
};

} // namespace ipxp::process::nettisa
