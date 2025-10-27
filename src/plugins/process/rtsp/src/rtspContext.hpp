/**
 * @file
 * @brief Export data of RTSP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <boost/static_string.hpp>

namespace ipxp::process::rtsp {

/**
 * @struct RTSPContext
 * @brief Stores parsed RTSP data that will be exported.
 */
struct RTSPContext {
	constexpr static std::size_t MAX_METHOD_LENGTH = 10;
	boost::static_string<MAX_METHOD_LENGTH> method;

	constexpr static std::size_t MAX_STRING_LENGTH = 128;
	boost::static_string<MAX_STRING_LENGTH> userAgent;
	boost::static_string<MAX_STRING_LENGTH> uri;
	boost::static_string<MAX_STRING_LENGTH> server;

	constexpr static std::size_t MAX_CONTENT_TYPE_LENGTH = 32;
	boost::static_string<MAX_CONTENT_TYPE_LENGTH> contentType;

	uint16_t code;

	struct {
		bool requestParsed {false};
		bool responseParsed {false};
	} processingState;
};

} // namespace ipxp::process::rtsp
