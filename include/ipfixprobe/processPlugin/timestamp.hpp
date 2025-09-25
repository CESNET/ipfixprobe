#pragma once

#include <iostream>
#include <cstdint>
#include <chrono>

namespace ipxp {

class Timestamp {
	constexpr static uint64_t NS_IN_SEC = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::seconds(1)).count();
	constexpr static uint64_t USEC_IN_SEC = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::seconds(1)).count();
	constexpr static uint64_t NS_IN_USEC = NS_IN_SEC / USEC_IN_SEC;

public:
	uint64_t ns;

	constexpr Timestamp() noexcept
	: ns(0)
	{
	}

	constexpr Timestamp(const timeval tv) noexcept
	: ns(static_cast<uint64_t>(tv.tv_sec) * NS_IN_SEC + static_cast<uint64_t>(tv.tv_usec) * USEC_IN_SEC)
	{
	}

	constexpr Timestamp operator-(const Timestamp& other) const noexcept
	{
		Timestamp ts;
		ts.ns = ns - other.ns;
		return ts;
	}

	constexpr timeval toTimeval() const noexcept
	{
		return {static_cast<time_t>(ns / NS_IN_SEC), static_cast<suseconds_t>((ns % NS_IN_SEC) / NS_IN_USEC)};
	}

	constexpr auto operator<=>(const Timestamp& other) const noexcept
	{
		return ns <=> other.ns;
	}

};

inline std::ostream& operator<<(std::ostream& os, const Timestamp& ts)
{
	(void) ts;

	os << "Timestamp{}";
	return os;
}

} // namespace ipxp
