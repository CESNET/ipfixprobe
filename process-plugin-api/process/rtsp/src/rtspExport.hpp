#pragma once

#include <boost/static_string.hpp>

namespace ipxp
{

struct RTSPExport {
	boost::static_string<10> method;
	boost::static_string<128> userAgent;
	boost::static_string<128> uri;
	
	uint16_t code;
	boost::static_string<32> contentType;
	boost::static_string<128> server;
};  

} // namespace ipxp

