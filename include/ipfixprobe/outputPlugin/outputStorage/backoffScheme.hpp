#pragma once

#include <cstdint>
#include <ranges>
#include <thread>

namespace ipxp::output {

class BackoffScheme {
public:
	explicit BackoffScheme(
		const uint32_t shortWaitThreshold,
		const uint32_t longWaitThreshold) noexcept
		: m_shortWaitThreshold(shortWaitThreshold)
		, m_longWaitThreshold(shortWaitThreshold + longWaitThreshold)
	{
	}

	bool backoff() noexcept
	{
		if (m_waitCounter < m_shortWaitThreshold) {
			for (volatile const auto _ : std::views::iota(0, 10'000)) {}
		} else if (m_waitCounter < m_longWaitThreshold) {
			std::this_thread::yield();
		} else {
			return false;
		}
		++m_waitCounter;
		return true;
	}

private:
	const uint32_t m_shortWaitThreshold;
	const uint32_t m_longWaitThreshold;
	uint32_t m_waitCounter {0};
};

} // namespace ipxp::output