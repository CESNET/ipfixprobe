/**
 * @file
 * @brief Export data of NTP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <boost/static_string/static_string.hpp>

namespace ipxp::process::ntp {

/**
 * @struct NetworkTimeContext
 * @brief Struct representing NTP flow statistics.
 */
struct NetworkTimeContext {
	uint8_t leap;
	uint8_t version;
	uint8_t mode;
	uint8_t stratum;
	uint8_t poll;
	uint8_t precision;
	uint32_t delay;
	uint32_t dispersion;

	constexpr static std::size_t MAX_IP4_AS_TEXT_LENGTH = 15;
	boost::static_string<MAX_IP4_AS_TEXT_LENGTH> referenceId;

	constexpr static std::size_t MAX_TIMESTAMP_AS_TEXT_LENGTH = 30;
	boost::static_string<MAX_TIMESTAMP_AS_TEXT_LENGTH> reference;
	boost::static_string<MAX_TIMESTAMP_AS_TEXT_LENGTH> origin;
	boost::static_string<MAX_TIMESTAMP_AS_TEXT_LENGTH> receive;
	boost::static_string<MAX_TIMESTAMP_AS_TEXT_LENGTH> sent;
};

} // namespace ipxp::process::ntp
