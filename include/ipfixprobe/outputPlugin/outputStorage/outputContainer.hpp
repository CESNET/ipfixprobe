#pragma once

// #include "../../processPlugin/flowRecord.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

template<typename ElementType>
struct OutputContainer {
	// constexpr static std::size_t SIZE = 64;
	constexpr static std::size_t SIZE = 1;
	boost::container::static_vector<ElementType, SIZE> storage;
	std::atomic<bool> written {false};
	std::atomic<uint8_t> readTimes {0};
	std::atomic<bool> read {0};
};

} // namespace ipxp::output