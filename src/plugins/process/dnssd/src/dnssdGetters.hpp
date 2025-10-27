/**
 * @file dnssdGetters.hpp
 * @brief Getters for DNSSD plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "dnssdContext.hpp"

#include <utils/stringViewUtils.hpp>

namespace ipxp::process::dnssd {

inline constexpr const DNSSDContext& asDNSContext(const void* context) noexcept
{
	return *static_cast<const DNSSDContext*>(context);
}

// DNSSDField::DNSSD_QUERIES
inline constexpr auto getDNSSDQueriesField
	= [](const void* context) { return toStringView(asDNSContext(context).queries); };

// DNSSDField::DNSSD_RESPONSES
inline constexpr auto getDNSSDResponsesField
	= [](const void* context) { return toStringView(asDNSContext(context).responses); };

} // namespace ipxp::process::dnssd
