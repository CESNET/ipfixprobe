#pragma once

#include <span>
#include <string_view>
#include <cstdint>
#include <cstddef>

#include "dnsName.hpp"
#include "dnsQueryType.hpp"

namespace ipxp
{
    
/**
 * @brief Parser record structure, common structure for answer, authority and additional records
 */
struct DNSRecord {
    DNSName name; 
    DNSQueryType type;
    uint16_t recordClass;
    uint32_t timeToLive;
    std::span<const std::byte> data;

    std::string toString() const noexcept;
};

} // namespace ipxp
