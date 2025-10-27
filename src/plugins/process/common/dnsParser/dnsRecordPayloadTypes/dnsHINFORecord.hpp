/**
 * @file
 * @brief Provides DNS HINFO record structure.
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
 * @struct DNSHINFORecord
 * @brief Represents a DNS HINFO record containing CPU and Operating System information.
 *
 * This structure provides functionality to create a DNS HINFO record from a byte payload
 * and to convert the record to its string representation.
 */
struct DNSHINFORecord {
	DNSName cpu;
	DNSName operatingSystem;

	static std::optional<DNSHINFORecord> createFrom(
		std::span<const std::byte> payload,
		std::span<const std::byte> fullDNSPayload) noexcept
	{
		auto res = std::make_optional<DNSHINFORecord>();

		const std::optional<DNSName> cpu = DNSName::createFrom(payload, fullDNSPayload);
		if (!cpu.has_value()) {
			return std::nullopt;
		}
		res->cpu = *cpu;

		const std::optional<DNSName> operatingSystem
			= DNSName::createFrom(payload.subspan(cpu->length()), fullDNSPayload);
		if (!operatingSystem.has_value()) {
			return std::nullopt;
		}
		res->operatingSystem = *operatingSystem;

		return res;
	}

	std::string toDNSString() const noexcept
	{
		return cpu.toString() + " " + operatingSystem.toString();
	}
};

} // namespace ipxp
