/**
 * @file
 * @brief Provides OPT record structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp {

/**
 * @brief Parser OPT record structure
 */
struct OPTRecord {
	uint16_t payloadSize; /**< OPT record payload size */
	bool dnssecOkBit; /**< DNSSEC OK bit */
};

} // namespace ipxp
