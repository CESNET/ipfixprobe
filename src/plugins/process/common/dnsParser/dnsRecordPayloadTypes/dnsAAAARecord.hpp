/**
 * @file
 * @brief Provides DNS AAAA record structure.
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
 * @struct DNSAAAARecord
 * @brief Represents a DNS AAAA record containing an IPv6 address.
 *
 * This structure provides functionality to create a DNS AAAA record from a byte payload
 * and to convert the IPv6 address to its string representation.
 */
struct DNSAAAARecord {
	std::span<const std::byte, 16> address;

	constexpr static std::optional<DNSAAAARecord>
	createFrom(std::span<const std::byte> payload) noexcept
	{
		auto res = std::make_optional<DNSAAAARecord>(payload.first<16>());
		if (payload.size() < res->address.size()) {
			return std::nullopt;
		}

		res->address = payload.first<16>();
		return res;
	}

	std::string toDNSString() const noexcept
	{
		std::ostringstream oss;

		std::array<char, INET6_ADDRSTRLEN> addressStr;
		inet_ntop(AF_INET6, address.data(), addressStr.data(), INET6_ADDRSTRLEN);
		oss << address.data();

		return oss.str();
	}
};

} // namespace ipxp
