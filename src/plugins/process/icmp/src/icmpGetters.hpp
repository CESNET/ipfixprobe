/**
 * @file icmpGetters.hpp
 * @brief Getters for ICMP plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "icmpContext.hpp"

namespace ipxp::process::icmp {

inline constexpr const ICMPContext& asICMPContext(const void* context)
{
	return *reinterpret_cast<const ICMPContext*>(context);
}

inline constexpr auto getICMPTypeCodeField
	= [](const void* context) { return asICMPContext(context).typeCode; };

inline constexpr auto getICMPCodeField = [](const void* context) {
	return static_cast<uint8_t>(asICMPContext(context).typeCode & 0x00FF);
};

inline constexpr auto getICMPTypeField = [](const void* context) {
	return static_cast<uint8_t>((asICMPContext(context).typeCode & 0xFF00) >> 8);
};

} // namespace ipxp::process::icmp
