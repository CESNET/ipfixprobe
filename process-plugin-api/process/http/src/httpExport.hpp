#pragma once

#include <boost/static_string.hpp>

namespace ipxp
{

struct HTTPExport {
	constexpr static std::size_t MAX_METHOD_LENGTH = 16;
	boost::static_string<MAX_METHOD_LENGTH> method;

	constexpr static std::size_t MAX_HOST_LENGTH = 64;
	boost::static_string<MAX_HOST_LENGTH> host;

	constexpr static std::size_t MAX_URI_LENGTH = 128;
	boost::static_string<MAX_URI_LENGTH> uri;

	constexpr static std::size_t MAX_USER_AGENT_LENGTH = 128;
	boost::static_string<MAX_USER_AGENT_LENGTH> user_agent;

	constexpr static std::size_t MAX_REFERER_LENGTH = 128;
	boost::static_string<MAX_REFERER_LENGTH> referer;

	constexpr static std::size_t MAX_CONTENT_TYPE_LENGTH = 32;
	boost::static_string<MAX_CONTENT_TYPE_LENGTH> content_type;

	constexpr static std::size_t MAX_SERVER_LENGTH = 32;
	boost::static_string<MAX_SERVER_LENGTH> server;

	constexpr static std::size_t MAX_COOKIES_LENGTH = 512;
	boost::static_string<MAX_COOKIES_LENGTH> cookies;

	uint16_t code;
};

} // namespace ipxp

