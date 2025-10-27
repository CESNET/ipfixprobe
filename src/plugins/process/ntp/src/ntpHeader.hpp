/**
 * @file
 * @brief NTP header structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::ntp {

/**
 * @union NetworkTimeHeader
 * @brief Union representing NTP header.
 */
union NetworkTimeHeader {
	NetworkTimeHeader(const uint8_t raw) noexcept
		: raw(raw)
	{
	}

	struct {
		uint8_t leap : 2;
		uint8_t version : 2;
		uint8_t mode : 2;
	} bitfields;

	uint8_t raw;
};

static_assert(sizeof(NetworkTimeHeader) == 1, "Unexpected NetworkTimeHeaer size");

} // namespace ipxp::process::ntp
