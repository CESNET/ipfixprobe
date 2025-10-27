/**
 * @file openvpnGetters.hpp
 * @brief Getters for OpenVPN plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */
#pragma once

#include "openvpnContext.hpp"

namespace ipxp::process::ovpn {

inline constexpr const OpenVPNContext& asOpenVPNContext(const void* context) noexcept
{
	return *static_cast<const OpenVPNContext*>(context);
}

// OpenVPNField::OVPN_CONF_LEVEL
inline constexpr auto getOVPNConfidenceLevelField
	= [](const void* context) { return asOpenVPNContext(context).vpnConfidence; };

} // namespace ipxp::process::ovpn
