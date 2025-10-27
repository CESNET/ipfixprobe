/**
 * @file
 * @brief Export data of OVPN plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "openvpnProcessingState.hpp"

#include <array>
#include <optional>
#include <span>

#include <boost/container/static_vector.hpp>

namespace ipxp::process::ovpn {

/**
 * @struct OpenVPContext
 * @brief Struct representing OVPN export data - confidence level and current processing state.
 */
struct OpenVPNContext {
	uint8_t vpnConfidence;

	OpenVPNProcessingState processingState;
};

} // namespace ipxp::process::ovpn
