/**
 * @file
 * @brief Provides DNS ISDN record structure.
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
 * @struct DNSISDNRecord
 * @brief Represents a DNS ISDN record containing ISDN address and subaddress.
 *
 * This structure provides functionality to create a DNS ISDN record from a byte payload
 * and to convert the record to its string representation.
 */
struct DNSISDNRecord {
	DNSName isdnAddress;
	DNSName subaddress;

	static std::optional<DNSISDNRecord> createFrom(
		std::span<const std::byte> payload,
		std::span<const std::byte> fullDNSPayload) noexcept
	{
		auto res = std::make_optional<DNSISDNRecord>();

		const std::optional<DNSName> isdnAddress = DNSName::createFrom(payload, fullDNSPayload);
		if (!isdnAddress.has_value()) {
			return std::nullopt;
		}
		res->isdnAddress = *isdnAddress;

		const std::optional<DNSName> subaddress
			= DNSName::createFrom(payload.subspan(isdnAddress->length()), fullDNSPayload);
		if (!subaddress.has_value()) {
			return std::nullopt;
		}
		res->subaddress = *subaddress;

		return res;
	}

	std::string toDNSString() const noexcept
	{
		return isdnAddress.toString() + " " + subaddress.toString();
	}
};

} // namespace ipxp
