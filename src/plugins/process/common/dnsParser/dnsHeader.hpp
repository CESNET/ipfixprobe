/**
 * @file
 * @brief Provides DNS header structure.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "dnsHeaderFlags.hpp"

#include <cstdint>

namespace ipxp {

/**
 * @brief DNS header
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
