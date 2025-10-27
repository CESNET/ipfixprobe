
/**
 * @file vlanGetters.hpp
 * @brief Getters for VLAN plugin fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "vlanContext.hpp"

namespace ipxp::process::vlan {

inline constexpr const VLANContext& asVLANContext(const void* context) noexcept
{
	return *static_cast<const VLANContext*>(context);
}

// VLANField::VLAN_ID
inline constexpr auto getVLANIdField
	= [](const void* context) { return asVLANContext(context).vlanId; };

} // namespace ipxp::process::vlan