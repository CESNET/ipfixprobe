/**
 * @file
 * @brief Implements DNS section parsing functionality.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "dnsSection.hpp"

#include "dnsSectionReader.hpp"

#include <algorithm>
#include <optional>
#include <ranges>
#include <span>

namespace ipxp {

std::optional<DNSSection> DNSSection::parseSection(
	std::span<const std::byte> section,
	std::span<const std::byte> fullDNSPayload,
	const std::size_t recordsCount) noexcept
{
	auto res = std::make_optional<DNSSection>();
	DNSSectionReader reader;
	std::ranges::copy(
		reader.getRange(recordsCount, section, fullDNSPayload)
			| std::views::take(res->records.capacity()),
		std::back_inserter(res->records));

	if (!reader.parsedSuccessfully()) {
		return std::nullopt;
	}

	res->size = 0;
	if (recordsCount != 0) {
		res->size = static_cast<std::size_t>(
			std::distance(section.begin(), res->records.back().payload.getSpan().end()));
	}
	return res;
}

} // namespace ipxp
