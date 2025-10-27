/**
 * @file netbiosGetters.hpp
 * @brief Getters for NetBIOS plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "netbiosContext.hpp"

#include <utils/stringViewUtils.hpp>

namespace ipxp::process::netbios {

inline constexpr const NetBIOSContext& asNetBIOSContext(const void* context) noexcept
{
	return *static_cast<const NetBIOSContext*>(context);
}

// NetBIOSField::NB_NAME
inline constexpr auto getNBNameField
	= [](const void* context) { return toStringView(asNetBIOSContext(context).name); };

// NetBIOSField::NB_SUFFIX
inline constexpr auto getNBSuffixField
	= [](const void* context) { return static_cast<uint8_t>(asNetBIOSContext(context).suffix); };

} // namespace ipxp::process::netbios
