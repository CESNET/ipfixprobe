/**
 * @file dnsSectionReader.hpp
 * @brief Declaration of DNSSectionReader for parsing DNS sections.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a ranges of DNS records from DNS section payload.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "dnsRecord.hpp"

#include <optional>
#include <ranges>
#include <span>
#include <tuple>

#include <readers/rangeReader/generator.hpp>
#include <readers/rangeReader/rangeReader.hpp>

namespace ipxp {

class DNSSectionReader : public RangeReader {
public:
	auto getRange(
		std::size_t itemCount,
		std::span<const std::byte> fullDNSPayload,
		std::span<const std::byte> section) noexcept
	{
		return Generator(
			[this, section, itemCount, fullDNSPayload]() mutable -> std::optional<DNSRecord> {
				auto res = std::make_optional<DNSRecord>();
				if (itemCount == 0) {
					setSuccess();
					return std::nullopt;
				}
				itemCount--;

				std::optional<DNSName> name = DNSName::createFrom(section, fullDNSPayload);
				if (!name.has_value()) {
					return std::nullopt;
				}
				if (name->length() + 3 * sizeof(uint16_t) + sizeof(uint32_t) > section.size()) {
					return std::nullopt;
				}
				res->name = std::move(*name);

				res->type = static_cast<DNSQueryType>(
					ntohs(*reinterpret_cast<const uint16_t*>(section.data() + name->length())));

				res->recordClass = ntohs(*reinterpret_cast<const uint16_t*>(
					section.data() + name->length() + sizeof(res->type)));

				res->timeToLive = ntohl(*reinterpret_cast<const uint32_t*>(
					section.data() + name->length() + 2 * sizeof(uint16_t)));

				const uint16_t rawDataLength = ntohs(*reinterpret_cast<const uint16_t*>(
					section.data() + name->length() + 2 * sizeof(uint16_t) + sizeof(uint32_t)));
				if (name->length() + 3 * sizeof(uint16_t) + sizeof(uint32_t) + rawDataLength
					> section.size()) {
					return std::nullopt;
				}

				std::span<const std::byte> rawData = section.subspan(
					name->length() + 3 * sizeof(uint16_t) + sizeof(uint32_t),
					rawDataLength);
				res->payload = DNSRecordPayload(rawData, fullDNSPayload, res->type);

				section = section.subspan(
					name->length() + 3 * sizeof(uint16_t) + sizeof(uint32_t) + rawDataLength);

				return res;
			});
	}
};

} // namespace ipxp
