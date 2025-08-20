#pragma once

#include <iostream>

namespace ipxp {

struct MacAddress {};

inline std::ostream& operator<<(std::ostream& os, const MacAddress& mac)
{
	(void) mac;

	os << "MacAddress{}";
	return os;
}

} // namespace ipxp
