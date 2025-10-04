/**
 * @file
 * @brief Provides DNS section structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "dnsRecord.hpp"

#include <cstddef>

#include <boost/container/static_vector.hpp>

namespace ipxp {

/**
 * @struct DNSSection
 * @brief Represents a section of DNS records, such as answers, authority, or additional records.
 * This structure holds a collection of DNS records and provides functionality to parse
 * a section from raw DNS packet data.
 */
struct DNSSection {
	constexpr static std::size_t MAX_RECORDS = 20;

	boost::container::static_vector<DNSRecord, MAX_RECORDS> records;
	std::size_t size;

	static std::optional<DNSSection> parseSection(
		std::span<const std::byte> section,
		std::span<const std::byte> fullDNSPayload,
		const std::size_t recordsCount) noexcept;
};

} // namespace ipxp
