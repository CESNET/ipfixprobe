#include "dnsSection.hpp"

#include <span>
#include <ranges>
#include <optional>
#include <algorithm>

#include "dnsSectionReader.hpp"



namespace ipxp
{
    
std::optional<DNSSection>
DNSSection::parseSection(
    std::span<const std::byte> section,
    std::span<const std::byte> fullDNSPayload,
    const std::size_t recordsCount) noexcept
{
    auto res = std::make_optional<DNSSection>();
    DNSSectionReader reader(recordsCount, section, fullDNSPayload);
    std::ranges::copy(reader | 
        std::views::take(res->records.capacity()), 
        std::back_inserter(res->records));
    
    if (!reader.parsedSuccessfully()) {
        return std::nullopt;
    }

    res->size = 0;
    if (recordsCount != 0) {
        res->size = static_cast<std::size_t>(std::distance(
            section.begin(),
            res->records.back().payload.getSpan().end()));
    }
    return res;
}


} // namespace ipxp
