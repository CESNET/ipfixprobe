/**
 * @file
 * @brief Export fields of bstats plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp {

/**
 * @enum BurstStatsFields
 * @brief Enumerates the fields exported by the BurstStats plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class BurstStatsFields : std::size_t {
	SBI_BRST_PACKETS = 0,
	SBI_BRST_BYTES,
	SBI_BRST_TIME_START,
	SBI_BRST_TIME_STOP,
	DBI_BRST_PACKETS,
	DBI_BRST_BYTES,
	DBI_BRST_TIME_START,
	DBI_BRST_TIME_STOP,
	FIELDS_SIZE,
};

} // namespace ipxp
