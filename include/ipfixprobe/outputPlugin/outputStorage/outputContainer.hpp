#pragma once

#include "../../processPlugin/flowRecord.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

template<typename ElementType>
struct OutputContainer {
	constexpr static std::size_t SIZE = 64;
	std::chrono::steady_clock::time_point creationTime;
	boost::container::static_vector<ElementType, SIZE> data;
	std::atomic<uint8_t> readTimes {0};
};

} // namespace ipxp::output