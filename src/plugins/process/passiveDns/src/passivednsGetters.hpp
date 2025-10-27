/**
 * @file passivednsGetters.hpp
 * @brief Getters for PassiveDNS plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "passivednsContext.hpp"

#include <utils/stringViewUtils.hpp>

namespace ipxp::process::passivedns {

inline constexpr const PassiveDNSContext& asPassiveDNSContext(const void* context) noexcept
{
	return *static_cast<const PassiveDNSContext*>(context);
}

// PassiveDNSField::DNS_ID
inline constexpr auto getDNSIDField
	= [](const void* context) { return asPassiveDNSContext(context).id; };

// PassiveDNSField::DNS_ATYPE
inline constexpr auto getDNSATYPEField
	= [](const void* context) { return static_cast<uint16_t>(asPassiveDNSContext(context).type); };

// PassiveDNSField::DNS_NAME
inline constexpr auto getDNSNameField
	= [](const void* context) { return toStringView(asPassiveDNSContext(context).name); };

// PassiveDNSField::DNS_RR_TTL
inline constexpr auto getDNSRRTTLField
	= [](const void* context) { return asPassiveDNSContext(context).timeToLive; };

// PassiveDNSField::DNS_IP
inline constexpr auto getDNSIPField
	= [](const void* context) { return asPassiveDNSContext(context).ip; };

} // namespace ipxp::process::passivedns
