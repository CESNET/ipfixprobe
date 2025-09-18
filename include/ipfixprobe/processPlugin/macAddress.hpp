#pragma once

#include <iostream>

namespace ipxp {

struct MACAddress {};

inline std::ostream& operator<<(std::ostream& os, const MACAddress& mac)
{
	(void) mac;

	os << "MacAddress{}";
	return os;
}

} // namespace ipxp
