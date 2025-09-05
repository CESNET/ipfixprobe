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
};

inline std::ostream& operator<<(std::ostream& os, const Timestamp& ts)
{
	(void) ts;

	os << "Timestamp{}";
	return os;
}

} // namespace ipxp
