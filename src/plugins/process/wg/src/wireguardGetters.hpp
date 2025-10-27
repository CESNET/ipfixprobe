
/**
 * @file wireguardGetters.hpp
 * @brief Getters for WireGuard plugin fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "wireguardContext.hpp"

#include <utils/spanUtils.hpp>

namespace ipxp::process::wireguard {

inline constexpr const WireguardContext& asWireguardContext(const void* context) noexcept
{
	return *static_cast<const WireguardContext*>(context);
}

// WireguardField::WG_CONF_LEVEL
inline constexpr auto getWireguardConfidenceLevelField
	= [](const void* context) { return asWireguardContext(context).confidence; };

// WireguardField::WG_SRC_PEER
inline constexpr auto getWireguardSrcPeerField
	= [](const void* context) { return *asWireguardContext(context).peer[Direction::Forward]; };

// WireguardField::WG_DST_PEER
inline constexpr auto getWireguardDstPeerField
	= [](const void* context) { return *asWireguardContext(context).peer[Direction::Reverse]; };

} // namespace ipxp::process::wireguard