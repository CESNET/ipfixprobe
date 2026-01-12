#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace ipxp::output {

struct OutputContainer {
	std::chrono::steady_clock::time_point creationTime;
	// Export data placeholder
	std::array<std::byte, 1024> data;

	// debug data
	static inline std::atomic<uint64_t> globalSequenceNumber;
	uint64_t sequenceNumber {0};
	std::atomic<uint8_t> readTimes {0};
};

} // namespace ipxp::output