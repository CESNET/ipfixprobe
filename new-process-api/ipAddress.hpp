#pragma once

#include <iostream>

namespace ipxp {

struct IpAddress {};

inline std::ostream& operator<<(std::ostream& os, const IpAddress& ip)
{
	(void) ip;

	os << "IpAddress{}";
	return os;
}

} // namespace ipxp
