/**
 * @file ipfixSetHeader.hpp
 * @brief Header of the IPFIX set. Each message contains multiple sets.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace ipxp::output::ipfix {

/**
 * @struct IPFIXSetHeader
 * @brief Structure representing the header of an IPFIX set.
 */
struct [[gnu::packed]] IPFIXSetHeader {
	uint16_t templateId; /// Template ID. For template sets, this is 2. For data sets, this is the
						 /// template ID > 256.
	uint16_t length; /// Length of the set, including the header, in bytes.
};

} // namespace ipxp::output::ipfix