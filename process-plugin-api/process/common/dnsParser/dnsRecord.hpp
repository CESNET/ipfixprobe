#pragma once

#include <span>
#include <string_view>
#include <cstdint>
#include <cstddef>

#include "dnsName.hpp"
#include "dnsQueryType.hpp"
#include "dnsRecordPayload.hpp"

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
    DNSRecordPayload payload;
};

} // namespace ipxp
