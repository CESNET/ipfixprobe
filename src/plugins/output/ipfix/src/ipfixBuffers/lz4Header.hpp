/**
 * @file lz4Header.hpp
 * @brief Header of the lz4 compressed data. Located before each compressed IPFIX message.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace ipxp::output::ipfix {

/**
 * @struct LZ4Header
 * @brief Structure representing the header of LZ4 compressed data.
 *
 */
struct [[gnu::packed]] LZ4Header {
	uint32_t magicNumber; /// Magic number identifying LZ4 compressed data.
	uint32_t size; /// Size of the uncompressed data.
};

} // namespace ipxp::output::ipfix