#pragma once

#include <boost/container/static_vector.hpp>

namespace ipxp
{

struct DNSSDExport {
	boost::container::static_vector<std::string_view, 30> requests;
};  

} // namespace ipxp

