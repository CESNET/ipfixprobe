
/**
 * @file ssdpGetters.hpp
 * @brief Getters for SSDP plugin fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "ssdpContext.hpp"

#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::ssdp {

inline constexpr const SSDPContext& asSSDPContext(const void* context) noexcept
{
	return *static_cast<const SSDPContext*>(context);
}

// SSDPField::SSDP_NT
inline constexpr auto getSSDPNTField
	= [](const void* context) { return toStringView(asSSDPContext(context).notificationType); };

// SSDPField::SSDP_ST
inline constexpr auto getSSDPSearchTargetField
	= [](const void* context) { return toStringView(asSSDPContext(context).searchTarget); };

// SSDPField::SSDP_SERVER
inline constexpr auto getSSDPServerField
	= [](const void* context) { return toStringView(asSSDPContext(context).server); };

// SSDPField::SSDP_USER_AGENT
inline constexpr auto getSSDPUserAgentField
	= [](const void* context) { return toStringView(asSSDPContext(context).userAgent); };

// SSDPField::SSDP_LOCATION_PORT
inline constexpr auto getSSDPLocationPortField
	= [](const void* context) { return asSSDPContext(context).port; };

} // namespace ipxp::process::ssdp