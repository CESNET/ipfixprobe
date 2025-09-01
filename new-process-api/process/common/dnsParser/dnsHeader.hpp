#pragma once

#include <cstdint>

#include "dnsHeaderFlags.hpp"

namespace ipxp
{
    
/**
 * @brief DNS header structure
 */
struct DNSHeader {
    uint16_t id; /**< DNS packet ID */
    DNSHeaderFlags flags; /**< DNS packet flags */
    uint16_t questionRecordCount; /**< Number of questions in the packet */
    uint16_t answerRecordCount; /**< Number of answers in the packet */
    uint16_t authorityRecordCount; /**< Number of authority records in the packet */
    uint16_t additionalRecordCount; /**< Number of additional records in the packet */
};


} // namespace ipxp
