/**
 * @file
 * @brief Provides DNS TXT record structure.
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
 * @struct DNSTXTRecord
 * @brief Represents a DNS TXT record containing text data.
 *
 * This structure provides functionality to create a DNS TXT record from a byte payload
 * and to convert the record to its string representation.
 */
struct DNSTXTRecord {
	// DNSName content;
	std::string content;

	static std::optional<DNSTXTRecord> createFrom(
		std::span<const std::byte> payload,
		std::span<const std::byte> fullDNSPayload) noexcept
	{
		auto res = std::make_optional<DNSTXTRecord>();

		/*const std::optional<DNSName> txt
			= DNSName::createFrom(payload, fullDNSPayload);
		if (!txt.has_value() || txt->length() == 0) {
			return std::nullopt;
		}
		res->content = *txt;
*/
		res->content = std::string(reinterpret_cast<const char*>(payload.data()), payload.size());
		return res;
	}

	std::string toDNSString() const noexcept
	{
		std::string res = content;
		const std::size_t firstPoint = res.find('.');
		if (firstPoint != std::string::npos) {
			res[firstPoint] = ' ';
		}

		return res;
	}
};

} // namespace ipxp
