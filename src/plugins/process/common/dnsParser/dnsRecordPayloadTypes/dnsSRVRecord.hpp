/**
 * @file
 * @brief Provides DNS SRV record structure.
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
 * @struct DNSSRVRecord
 * @brief Represents a DNS SRV record containing priority, weight, port, and target.
 *
 * This structure provides functionality to create a DNS SRV record from a byte payload
 * and to convert the record to its string representation.
 */
struct DNSSRVRecord {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	DNSName target;

	constexpr static std::optional<DNSSRVRecord> createFrom(
		std::span<const std::byte> payload,
		std::span<const std::byte> fullDNSPayload) noexcept
	{
		auto res = std::make_optional<DNSSRVRecord>();

		if (payload.size() < 3 * sizeof(uint16_t)) {
			return std::nullopt;
		}

		const auto* svr = reinterpret_cast<const DNSSRVRecord*>(payload.data());
		res->priority = ntohs(svr->priority);
		res->weight = ntohs(svr->weight);
		res->port = ntohs(svr->port);
		const std::optional<DNSName> target
			= DNSName::createFrom(payload.subspan(sizeof(DNSSRVRecord)), fullDNSPayload);
		if (!target.has_value()) {
			return std::nullopt;
		}
		res->target = *target;

		return res;
	}

	std::string toDNSString() const noexcept
	{
		std::ostringstream oss;
		oss << priority << " " << weight << " " << port;
		return oss.str();
	}
};

} // namespace ipxp
