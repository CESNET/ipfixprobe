/**
 * @file
 * @brief Export fields of DNS-SD plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::dnssd {

/**
 * @enum DNSSDFields
 * @brief Enumerates the fields exported by the DNSSD plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class DNSSDFields : std::size_t {
	DNSSD_QUERIES = 0,
	DNSSD_RESPONSES,
	FIELDS_SIZE,
};

} // namespace ipxp::process::dnssd
