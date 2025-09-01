#pragma once

#include <cstdint>

namespace ipxp
{

/**
 * @brief Parser OPT record structure
 */
struct OPTRecord {
    uint16_t payloadSize; /**< OPT record payload size */
    bool dnssecOkBit; /**< DNSSEC OK bit */
};


} // namespace ipxp
