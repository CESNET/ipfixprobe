#pragma once

#include <iostream>

namespace ipxp {

struct Timestamp {};

inline std::ostream& operator<<(std::ostream& os, const Timestamp& ts)
{
	(void) ts;

	os << "Timestamp{}";
	return os;
}

} // namespace ipxp
