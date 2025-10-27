/**
 * @file
 * @brief Export fields of osquery plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::osquery {

/**
 * @enum BurstStatsFields
 * @brief Enumerates the fields exported by the BurstStats plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class OSQueryFields : std::size_t {
	OSQUERY_PROGRAM_NAME = 0,
	OSQUERY_USERNAME,
	OSQUERY_OS_NAME,
	OSQUERY_OS_MAJOR,
	OSQUERY_OS_MINOR,
	OSQUERY_OS_BUILD,
	OSQUERY_OS_PLATFORM,
	OSQUERY_OS_PLATFORM_LIKE,
	OSQUERY_OS_ARCH,
	OSQUERY_KERNEL_VERSION,
	OSQUERY_SYSTEM_HOSTNAME,
	FIELDS_SIZE,
};

} // namespace ipxp::process::osquery
