/**
 * @file sipGetters.hpp
 * @brief Getters for SIP plugin fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "sipContext.hpp"

#include <utils/stringViewUtils.hpp>

namespace ipxp::process::sip {

inline constexpr const SIPContext& asSIPContext(const void* context) noexcept
{
	return *static_cast<const SIPContext*>(context);
}

// SIPField::SIP_MSG_TYPE
inline constexpr auto getSIPMsgTypeField
	= [](const void* context) { return asSIPContext(context).messageType; };

// SIPField::SIP_STATUS_CODE
inline constexpr auto getSIPStatusCodeField
	= [](const void* context) { return asSIPContext(context).statusCode; };

// SIPField::SIP_CSEQ
inline constexpr auto getSIPCSeqField
	= [](const void* context) { return toStringView(asSIPContext(context).commandSequence); };

// SIPField::SIP_CALLING_PARTY
inline constexpr auto getSIPCallingPartyField
	= [](const void* context) { return toStringView(asSIPContext(context).callingParty); };

// SIPField::SIP_CALLED_PARTY
inline constexpr auto getSIPCalledPartyField
	= [](const void* context) { return toStringView(asSIPContext(context).calledParty); };

// SIPField::SIP_CALL_ID
inline constexpr auto getSIPCallIdField
	= [](const void* context) { return toStringView(asSIPContext(context).callId); };

// SIPField::SIP_USER_AGENT
inline constexpr auto getSIPUserAgentField
	= [](const void* context) { return toStringView(asSIPContext(context).userAgent); };

// SIPField::SIP_REQUEST_URI
inline constexpr auto getSIPRequestURIField
	= [](const void* context) { return toStringView(asSIPContext(context).requestURI); };

// SIPField::SIP_VIA
inline constexpr auto getSIPViaField
	= [](const void* context) { return toStringView(asSIPContext(context).via); };

} // namespace ipxp::process::sip