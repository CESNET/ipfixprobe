#pragma once

#include <cstdint>

namespace ipxp
{

struct NetTimeSeriesExport {
	float mean;
	uint16_t min;
	uint16_t max;
	float stdev;
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
		uint64_t prevTime;
		uint64_t sumPayload;
	} processingState;
};  

} // namespace ipxp

