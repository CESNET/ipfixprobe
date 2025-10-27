/**
 * @file
 * @brief Provides DNS PTR record structure.
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
 * @struct DNSPTRRecord
 * @brief Represents a DNS PTR record containing a domain name.
 *
 * This structure provides functionality to create a DNS PTR record from a byte payload
 * and to convert the record to its string representation.
 */
struct DNSPTRRecord {
	DNSName name;

	static std::optional<DNSPTRRecord> createFrom(
		std::span<const std::byte> payload,
		std::span<const std::byte> fullDNSPayload) noexcept
	{
		auto res = std::make_optional<DNSPTRRecord>();

		const std::optional<DNSName> name = DNSName::createFrom(payload, fullDNSPayload);
		if (!name.has_value()) {
			return std::nullopt;
		}

		res->name = *name;
		return res;
	}

	std::string toDNSString() const noexcept { return name.toString(); }
};

} // namespace ipxp
