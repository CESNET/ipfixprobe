/**
 * @file
 * @brief Export fields of NTP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::ntp {

/**
 * @enum NetworkTimeFields
 * @brief Enumerates the fields exported by the NetworkTime plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class NetworkTimeFields : std::size_t {
	NTP_LEAP = 0,
	NTP_VERSION,
	NTP_MODE,
	NTP_STRATUM,
	NTP_POLL,
	NTP_PRECISION,
	NTP_DELAY,
	NTP_DISPERSION,
	NTP_REF_ID,
	NTP_REF,
	NTP_ORIG,
	NTP_RECV,
	NTP_SENT,
	FIELDS_SIZE,
};

} // namespace ipxp::process::ntp
