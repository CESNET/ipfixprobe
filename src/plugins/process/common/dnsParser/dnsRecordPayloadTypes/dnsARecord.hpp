/**
 * @file
 * @brief Provides DNS A record structure.
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
 * @struct DNSARecord
 * @brief Represents a DNS A record containing an IPv4 address.
 *
 * This structure provides functionality to create a DNS A record from a byte payload
 * and to convert the IPv4 address to its string representation.
 */
struct DNSARecord {
	uint32_t address;

	constexpr static std::optional<DNSARecord>
	createFrom(std::span<const std::byte> payload) noexcept
	{
		auto res = std::make_optional<DNSARecord>();

		if (payload.size() < sizeof(uint32_t)) {
			return std::nullopt;
		}

		res->address = *reinterpret_cast<const uint32_t*>(payload.data());

		return res;
	}

	std::string toDNSString() const noexcept
	{
		std::ostringstream oss;

		std::array<char, INET_ADDRSTRLEN> addressStr;
		inet_ntop(AF_INET, &address, addressStr.data(), INET_ADDRSTRLEN);
		oss << addressStr.data();

		return oss.str();
	}
};

} // namespace ipxp
