/**
 * @file
 * @brief Export fields of DNS plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp
{

/**
 * @enum DNSFields
 * @brief Enumerates the fields exported by the DNS plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class DNSFields : std::size_t {
	DNS_ID = 0,
	DNS_ANSWERS,
	DNS_RCODE,
	DNS_NAME,
	DNS_QTYPE,
	DNS_CLASS,
	DNS_RR_TTL,
	DNS_RLENGTH,
	DNS_RDATA,
	DNS_PSIZE,
	DNS_DO,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
