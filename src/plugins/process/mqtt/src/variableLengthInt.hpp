/**
 * @file
 * @brief Variable length integer used by MQTT protocol.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <utils/variableLengthType.hpp>

namespace ipxp::process::mqtt {

using VariableLengthInt = VariableLengthType<int32_t>;

/**
 * @brief Read variable integer as defined in
 * http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html.
 * @param payload Payload to read from.
 * @return Optional with read variable integer or nullopt if payload is too short.
 */
constexpr static std::optional<VariableLengthInt>
readVariableLengthInt(std::span<const std::byte> payload) noexcept
{
	VariableLengthInt res {0, 0};

	for (const std::byte byte : payload) {
		res.value <<= 8;
		res.value |= static_cast<int32_t>(byte);
		res.length++;

		if (const bool readNext = (static_cast<uint32_t>(byte) & 0b1000'0000U); !readNext) {
			return std::make_optional<VariableLengthInt>(res);
		}
	}

	return std::nullopt;
}

} // namespace ipxp