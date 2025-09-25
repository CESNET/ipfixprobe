#pragma once

#include <iostream>
#include <cstdint>

namespace ipxp {

struct Timestamp {
	uint64_t ns;

	constexpr Timestamp() noexcept
	: ns(0)
	{
	}

	constexpr Timestamp(const timeval tv) noexcept
	: ns(0)
	{
		// TODO
		(void)tv;
	}

	constexpr Timestamp operator-(const Timestamp& other) const noexcept
	{
		Timestamp ts;
		ts.ns = ns - other.ns;
		return ts;
	}

	constexpr uint64_t toSeconds() const noexcept
	{
		return ns / 1'000'000'000;
	}

	constexpr timeval toTimeval() const noexcept
	{
		// TODO use chrono
		timeval tv;
		tv.tv_sec = static_cast<time_t>(ns / 1'000'000'000);
		tv.tv_usec = static_cast<suseconds_t>((ns % 1'000'000'000) / 1'000);
		return tv;
	}

	constexpr bool operator<(const Timestamp& other) const noexcept
	{
		return ns < other.ns;
	}

	constexpr bool operator>(const Timestamp& other) const noexcept
	{
		return ns > other.ns;
	}
};

inline std::ostream& operator<<(std::ostream& os, const Timestamp& ts)
{
	(void) ts;

	os << "Timestamp{}";
	return os;
}

} // namespace ipxp
