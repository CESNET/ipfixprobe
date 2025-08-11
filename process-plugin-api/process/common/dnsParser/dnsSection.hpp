#pragma once

#include <boost/container/static_vector.hpp>
#include <cstddef>

#include "dnsRecord.hpp"

namespace ipxp
{
    
struct DNSSection {
	constexpr static std::size_t MAX_RECORDS = 20;

    boost::container::static_vector<DNSRecord, MAX_RECORDS> records;
    std::size_t size;

    constexpr static std::optional<DNSSection> parseSection(
    std::span<const std::byte> section,
    const std::byte* dnsBegin,
    const std::size_t recordsCount) noexcept;

};


} // namespace ipxp
