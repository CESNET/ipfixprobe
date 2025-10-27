/**
 * @file quicTypesCumulative.hpp
 * @brief Definition of QUICTypesCumulative union for QUIC plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace ipxp::process::quic {

union QUICTypesCumulative {
	struct {
		uint8_t quicBit : 1;
		uint8_t reserved : 2;
		uint8_t versionNegotiation : 1;
		uint8_t retry : 1;
		uint8_t handshake : 1;
		uint8_t zeroRTT : 1;
		uint8_t initial : 1;
	} bitfields;

	std::byte raw;
};

static_assert(sizeof(QUICTypesCumulative) == 1, "Invalid QUICTypesCumulative size");

} // namespace ipxp::process::quic
