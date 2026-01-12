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

} // namespace ipxp::output