#pragma once

#include <boost/static_string.hpp>

namespace ipxp {

struct SSDPData {
	constexpr static std::size_t MAX_URN_LENGTH = 511;
	boost::static_string<MAX_URN_LENGTH> notificationType;
	boost::static_string<MAX_URN_LENGTH> searchTarget;

	constexpr static std::size_t MAX_SERVER_LENGTH = 255;
	boost::static_string<MAX_SERVER_LENGTH> server;

	constexpr static std::size_t MAX_USER_AGENT_LENGTH = 255;
	boost::static_string<MAX_USER_AGENT_LENGTH> userAgent;

	uint16_t port;
};

} // namespace ipxp
