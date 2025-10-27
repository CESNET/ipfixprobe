/**
 * @file ntpGetters.hpp
 * @brief Getters for NTP plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "ntpContext.hpp"

#include <utils/stringViewUtils.hpp>

namespace ipxp::process::ntp {

inline constexpr const NetworkTimeContext& asNetworkTimeContext(const void* context) noexcept
{
	return *static_cast<const NetworkTimeContext*>(context);
}

// NetworkTimeField::NTP_LEAP
inline constexpr auto getNTPLeapField
	= [](const void* context) { return asNetworkTimeContext(context).leap; };

// NetworkTimeField::NTP_VERSION
inline constexpr auto getNTPVersionField
	= [](const void* context) { return asNetworkTimeContext(context).version; };

// NetworkTimeField::NTP_MODE
inline constexpr auto getNTPModeField
	= [](const void* context) { return asNetworkTimeContext(context).mode; };

// NetworkTimeField::NTP_STRATUM
inline constexpr auto getNTPStratumField
	= [](const void* context) { return asNetworkTimeContext(context).stratum; };

// NetworkTimeField::NTP_POLL
inline constexpr auto getNTPPollField
	= [](const void* context) { return asNetworkTimeContext(context).poll; };

// NetworkTimeField::NTP_PRECISION
inline constexpr auto getNTPPrecisionField
	= [](const void* context) { return asNetworkTimeContext(context).precision; };

// NetworkTimeField::NTP_DELAY
inline constexpr auto getNTPDelayField
	= [](const void* context) { return asNetworkTimeContext(context).delay; };

// NetworkTimeField::NTP_DISPERSION
inline constexpr auto getNTPDispersionField
	= [](const void* context) { return asNetworkTimeContext(context).dispersion; };

// NetworkTimeField::NTP_REF_ID
inline constexpr auto getNTPRefIdField
	= [](const void* context) { return toStringView(asNetworkTimeContext(context).referenceId); };

// NetworkTimeField::NTP_REF
inline constexpr auto getNTPRefField
	= [](const void* context) { return toStringView(asNetworkTimeContext(context).reference); };

// NetworkTimeField::NTP_ORIG
inline constexpr auto getNTPOrigField
	= [](const void* context) { return toStringView(asNetworkTimeContext(context).origin); };

// NetworkTimeField::NTP_RECV
inline constexpr auto getNTPRecvField
	= [](const void* context) { return toStringView(asNetworkTimeContext(context).receive); };

// NetworkTimeField::NTP_SENT
inline constexpr auto getNTPSentField
	= [](const void* context) { return toStringView(asNetworkTimeContext(context).sent); };

} // namespace ipxp::process::ntp