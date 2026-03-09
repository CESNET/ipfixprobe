#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ipxp::output {

static uint16_t getThreadId() noexcept
{
	static std::atomic_uint16_t threadCounter {0};
	static thread_local const uint16_t thisThreadIndex = threadCounter++;
	return thisThreadIndex;
}

template<typename DataType>
static DataType& getThreadLocalData() noexcept
{
	static thread_local DataType threadLocalData;
	return threadLocalData;
}

bool casMax(auto& atomicValue, const auto& newValue) noexcept
{
	std::size_t currentValue;
	do {
		currentValue = atomicValue.load(std::memory_order_acquire);
		if (currentValue >= newValue) {
			return false;
		}
	} while (!atomicValue.compare_exchange_weak(currentValue, newValue, std::memory_order_release));
	return true;
}

bool casMin(auto& atomicValue, const auto& newValue) noexcept
{
	std::size_t currentValue;
	do {
		currentValue = atomicValue.load(std::memory_order_acquire);
		if (currentValue <= newValue) {
			return false;
		}
	} while (!atomicValue.compare_exchange_weak(currentValue, newValue, std::memory_order_release));
	return true;
}

} // namespace ipxp::output