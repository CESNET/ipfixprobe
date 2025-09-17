#pragma once

#include <cstdint>

#include "dnsQueryType.hpp"
#include "dnsName.hpp"

namespace ipxp
{

/**
 * @brief Parser question structure
 */
struct DNSQuestion {
    DNSName name; /**< Question name field */
    DNSQueryType type; /**< Question type */
    uint16_t recordClass; /**< Question class */
};

} // namespace ipxp
