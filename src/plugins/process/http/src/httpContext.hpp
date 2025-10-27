/**
 * @file
 * @brief Export data of HTTP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <boost/static_string.hpp>

namespace ipxp::process::http {

/**
 * @struct HTTPContext
 * @brief Structure representing HTTP request/response data and its processing state.
 */
struct HTTPContext {
	constexpr static std::size_t MAX_METHOD_LENGTH = 16;
	boost::static_string<MAX_METHOD_LENGTH> method;

	constexpr static std::size_t MAX_HOST_LENGTH = 64;
	boost::static_string<MAX_HOST_LENGTH> host;

	constexpr static std::size_t MAX_URI_LENGTH = 128;
	boost::static_string<MAX_URI_LENGTH> uri;

	constexpr static std::size_t MAX_USER_AGENT_LENGTH = 128;
	boost::static_string<MAX_USER_AGENT_LENGTH> userAgent;

	constexpr static std::size_t MAX_REFERER_LENGTH = 128;
	boost::static_string<MAX_REFERER_LENGTH> referer;

	constexpr static std::size_t MAX_CONTENT_TYPE_LENGTH = 32;
	boost::static_string<MAX_CONTENT_TYPE_LENGTH> contentType;

	constexpr static std::size_t MAX_SERVER_LENGTH = 32;
	boost::static_string<MAX_SERVER_LENGTH> server;

	constexpr static std::size_t MAX_COOKIES_LENGTH = 512;
	boost::static_string<MAX_COOKIES_LENGTH> cookies;

	uint16_t statusCode;

	bool requestParsed {false};
	bool responseParsed {false};
};

} // namespace ipxp::process::http
