/**
 * @file
 * @brief Provides DNS question structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "dnsName.hpp"
#include "dnsQueryType.hpp"

#include <cstdint>

namespace ipxp {

/**
 * @brief Parser question structure
 */
struct DNSQuestion {
	DNSName name; /**< Question name field */
	DNSQueryType type; /**< Question type */
	uint16_t recordClass; /**< Question class */
};

} // namespace ipxp
