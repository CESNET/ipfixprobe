/**
 * @file
 * @brief Export data of SSDP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <boost/static_string.hpp>

namespace ipxp::process::ssdp {

/**
 * @struct SSDPContext
 * @brief Stores parsed SSDP data that will be exported.
 */
struct SSDPContext {
	constexpr static std::size_t MAX_URN_LENGTH = 511;
	boost::static_string<MAX_URN_LENGTH> notificationType;
	boost::static_string<MAX_URN_LENGTH> searchTarget;

	constexpr static std::size_t MAX_SERVER_LENGTH = 255;
	boost::static_string<MAX_SERVER_LENGTH> server;

	constexpr static std::size_t MAX_USER_AGENT_LENGTH = 255;
	boost::static_string<MAX_USER_AGENT_LENGTH> userAgent;

	uint16_t port;
};

} // namespace ipxp::process::ssdp
