/**
 * @file
 * @brief Provides endian-aware RTP header.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::ovpn {

struct RTPHeader {
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t csrcCount : 4;
	uint16_t extension : 1;
	uint16_t padding : 1;
	uint16_t version : 2;
	// next byte
	uint16_t payloadType : 7;
	uint16_t marker : 1;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version : 2;
	uint16_t padding : 1;
	uint16_t extension : 1;
	uint16_t csrcCount : 4;
	// next byte
	uint16_t marker : 1;
	uint16_t payloadType : 7;

#else // if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
#error "Please fix <endian.h>"
#endif // if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t sequenceNumber;
	uint32_t timestamp;
	uint32_t ssrc;
} __attribute__((packed));

static_assert(sizeof(RTPHeader) == 12, "RTPHeader size is incorrect");

} // namespace ipxp::process::ovpn
