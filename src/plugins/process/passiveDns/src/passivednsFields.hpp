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

namespace ipxp::process::passivedns {

/**
 * @enum PassiveDNSFields
 * @brief Enumerates the fields exported by the PassiveDNS plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class PassiveDNSFields : std::size_t {
	DNS_ID = 0,
	DNS_ATYPE,
	DNS_NAME,
	DNS_RR_TTL,
	DNS_IP,
	FIELDS_SIZE,
};

} // namespace ipxp::process::passivedns
