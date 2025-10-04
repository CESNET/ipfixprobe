/**
 * @file
 * @brief Provides DNS header flags structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp {

/**
 * @brief DNS header flags structure
 */
struct DNSHeaderFlags {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint16_t queryResponse : 1; /**< Query or response bit*/
	uint16_t operationCode : 4; /**< Operation code */
	uint16_t authorityAnswer : 1; /**< Authority answer */
	uint16_t truncation : 1; /**< Truncation bit*/
	uint16_t recursionDesired : 1; /**< Recursion desired */
	uint16_t recursionAvailable : 1; /**< Recursion available */
	uint16_t reserved : 3; /**< Reserved */
	uint16_t responseCode : 4; /**< Response code */
#else
	uint16_t responseCode : 4;
	uint16_t reserved : 3;
	uint16_t recursionAvailable : 1;
	uint16_t recursionDesired : 1;
	uint16_t truncation : 1;
	uint16_t authorityAnswer : 1;
	uint16_t operationCode : 4;
	uint16_t queryResponse : 1;
#endif
} __attribute__((packed));

static_assert(sizeof(DNSHeaderFlags) == 2, "Invalid DNSHeaderFlags size");

} // namespace ipxp
