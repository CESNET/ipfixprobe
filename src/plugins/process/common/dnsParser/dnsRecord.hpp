/**
 * @file
 * @brief Provides DNS record structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "dnsName.hpp"
#include "dnsQueryType.hpp"
#include "dnsRecordPayload.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace ipxp {

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
