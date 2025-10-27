/**
 * @file
 * @brief OVPN header opcodes.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::ovpn {

enum class OpenVPNOpcode : uint8_t {
	P_CONTROL_HARD_RESET_CLIENT_V1 = 0x01,
	P_CONTROL_HARD_RESET_CLIENT_V2 = 0x02,
	P_CONTROL_HARD_RESET_CLIENT_V3 = 0x03,
	P_CONTROL_HARD_RESET_SERVER_V1 = 0x04,
	P_CONTROL_HARD_RESET_SERVER_V2 = 0x05,
	P_CONTROL_SOFT_RESET_V1 = 0x06,
	P_CONTROL_V1 = 0x07,
	P_ACK_V1 = 0x08,
	P_DATA_V1 = 0x09,
	P_DATA_V2 = 0x0A
};

} // namespace ipxp::process::ovpn
