/**
 * @file
 * @brief Provides DNS MX record structure.
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
 * @struct DNSMXRecord
 * @brief Represents a DNS MX record containing preference and exchange name.
 *
 * This structure provides functionality to create a DNS MX record from a byte payload
 * and to convert the record to its string representation.
 */
struct DNSMXRecord {
	uint16_t preference;
	DNSName exchangeName;

	constexpr static std::optional<DNSMXRecord> createFrom(
		std::span<const std::byte> payload,
		std::span<const std::byte> fullDNSPayload) noexcept
	{
		auto res = std::make_optional<DNSMXRecord>();

		if (payload.size() < sizeof(uint16_t)) {
			return std::nullopt;
		}

		res->preference = ntohs(*reinterpret_cast<const uint16_t*>(payload.data()));
		const std::optional<DNSName> exchangeName
			= DNSName::createFrom(payload.subspan(sizeof(preference)), fullDNSPayload);
		if (!exchangeName.has_value()) {
			return std::nullopt;
		}

		res->exchangeName = *exchangeName;
		return res;
	}

	std::string toDNSString() const noexcept
	{
		std::ostringstream oss;
		oss << preference << " " << exchangeName.toString();
		return oss.str();
	}
};

} // namespace ipxp
