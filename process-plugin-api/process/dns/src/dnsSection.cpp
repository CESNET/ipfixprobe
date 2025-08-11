#include "dnsSection.hpp"

#include "dnsSectionReader.hpp"

namespace ipxp
{
    
constexpr
std::optional<DNSSection>
DNSSection::parseSection(
    std::span<const std::byte> section,
    const std::byte* dnsBegin,
    const std::size_t recordsCount) noexcept
{
    auto res = std::make_optional<DNSSection>();
    DNSSectionReader reader(section, recordsCount, dnsBegin);
    std::ranges::copy(reader | 
        std::views::take(res->records.capacity()), 
        std::back_inserter(res->records));
    
    if (!reader.parsedSuccessfully) {
        return std::nullopt;
    }

    res->size = 0;
    if (recordsCount != 0) {
        res->size = res->records.back().data.end() - section.begin();
    }
    return res;
}


} // namespace ipxp
