/**
 * @file
 * @brief Provides DNS KEY record structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <sstream>
#include <string>

#include <arpa/inet.h>

namespace ipxp {

/**
 * @struct DNSKEYRecord
 * @brief Represents a DNS KEY record containing flags, protocol, and algorithm.
 *
 * This structure provides functionality to create a DNS KEY record from a byte payload
 * and to convert the record to its string representation.
 */
struct DNSKEYRecord {
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	constexpr static std::optional<DNSKEYRecord>
	createFrom(std::span<const std::byte> payload) noexcept
	{
		auto res = std::make_optional<DNSKEYRecord>();

		if (payload.size() < sizeof(DNSKEYRecord)) {
			return std::nullopt;
		}

		const auto* dnsKey = reinterpret_cast<const DNSKEYRecord*>(payload.data());
		res->flags = ntohs(dnsKey->flags);
		res->protocol = dnsKey->protocol;
		res->algorithm = dnsKey->algorithm;

		return res;
	}

	std::string toDNSString() const noexcept
	{
		std::ostringstream oss;
		oss << flags << " " << static_cast<uint16_t>(protocol) << " "
			<< static_cast<uint16_t>(algorithm) << " <key>";
		return oss.str();
	}
};

} // namespace ipxp
