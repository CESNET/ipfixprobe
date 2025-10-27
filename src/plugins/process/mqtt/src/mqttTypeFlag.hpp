/**
 * @file
 * @brief MQTT type flag.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "mqttHeaderType.hpp"

#include <cstdint>

namespace ipxp::process::mqtt {

/**
 * @union MQTTTypeFlag
 * @brief Union representing MQTT type flags.
 */
union MQTTTypeFlag {
	MQTTTypeFlag(const uint8_t raw) noexcept
		: raw(raw)
	{
	}

	struct {
		MQTTHeaderType type : 4;
		uint8_t flag : 4;
	} bitfields;

	uint8_t raw;
};

static_assert(sizeof(MQTTTypeFlag) == 1, "Unexpected MQTTTypeFlag size");

} // namespace ipxp