/**
 * @file
 * @brief Provides DNS DS record structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "../dnsName.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <sstream>
#include <string>

namespace ipxp {

/**
 * @struct DNSDSRecord
 * @brief Represents a DNS DS record containing key tag, algorithm, and digest type.
 *
 * This structure provides functionality to create a DNS DS record from a byte payload
 * and to convert the record to its string representation.
 */
struct DNSDSRecord {
	uint16_t keytag;
	uint8_t algorithm;
	uint8_t digestType;

	constexpr static std::optional<DNSDSRecord>
	createFrom(std::span<const std::byte> payload) noexcept
	{
		auto res = std::make_optional<DNSDSRecord>();

		if (payload.size() < sizeof(uint16_t) + 2 * sizeof(uint8_t)) {
			return std::nullopt;
		}
		res->keytag = ntohs(*reinterpret_cast<const uint16_t*>(payload.data()));
		res->algorithm = *reinterpret_cast<const uint8_t*>(payload.data() + sizeof(res->keytag));
		res->digestType = *reinterpret_cast<const uint8_t*>(
			payload.data() + sizeof(res->keytag) + sizeof(res->algorithm));

		return res;
	}

	std::string toDNSString() const noexcept
	{
		std::ostringstream oss;
		oss << keytag << " " << static_cast<uint16_t>(algorithm) << " "
			<< static_cast<uint16_t>(digestType) << " <key>";
		return oss.str();
	}
};

} // namespace ipxp
