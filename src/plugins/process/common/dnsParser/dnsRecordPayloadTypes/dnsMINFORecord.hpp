/**
 * @file
 * @brief Provides DNS MINFO record structure.
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
 * @struct DNSMINFORecord
 * @brief Represents a DNS MINFO record containing RMAILBX and EMAILBX fields.
 *
 * This structure provides functionality to create a DNS MINFO record from a byte payload
 * and to convert the record to its string representation.
 */
struct DNSMINFORecord {
	DNSName rMailBox;
	DNSName eMailBox;

	static std::optional<DNSMINFORecord> createFrom(
		std::span<const std::byte> payload,
		std::span<const std::byte> fullDNSPayload) noexcept
	{
		auto res = std::make_optional<DNSMINFORecord>();

		const std::optional<DNSName> rMailBox = DNSName::createFrom(payload, fullDNSPayload);
		if (!rMailBox.has_value()) {
			return std::nullopt;
		}
		res->rMailBox = *rMailBox;

		const std::optional<DNSName> eMailBox
			= DNSName::createFrom(payload.subspan(rMailBox->length()), fullDNSPayload);
		if (!eMailBox.has_value()) {
			return std::nullopt;
		}
		res->eMailBox = *eMailBox;

		return res;
	}

	std::string toDNSString() const noexcept
	{
		std::ostringstream oss;
		oss << rMailBox.toString() << " " << eMailBox.toString();
		return oss.str();
	}
};

} // namespace ipxp
