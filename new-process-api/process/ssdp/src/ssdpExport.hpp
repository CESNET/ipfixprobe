#pragma once

#include <boost/static_string.hpp>

namespace ipxp
{

struct SSDPExport {
	constexpr static std::size_t MAX_URN_LENGTH = 511;
	constexpr static std::size_t MAX_SERVER_LENGTH = 255;
	constexpr static std::size_t MAX_USER_AGENT_LENGTH = 255;

	uint16_t port;
	boost::static_string<MAX_URN_LENGTH> notificationType;
	boost::static_string<MAX_URN_LENGTH> searchTarget;
	boost::static_string<MAX_SERVER_LENGTH> server;
	boost::static_string<MAX_USER_AGENT_LENGTH> userAgent;
};  

} // namespace ipxp

