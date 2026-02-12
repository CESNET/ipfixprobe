#pragma once

#include "../../processPlugin/flowRecord.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

struct OutputContainer {
	constexpr static std::size_t SIZE = 64;
	std::chrono::steady_clock::time_point creationTime;
	boost::container::static_vector<FlowRecordUniquePtr, SIZE> flows;

	// debug data
	static inline std::atomic<uint64_t> globalSequenceNumber;
	uint64_t sequenceNumber {0};
	std::atomic<uint8_t> readTimes {0};
};

} // namespace ipxp::output