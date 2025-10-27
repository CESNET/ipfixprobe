/**
 * @file dnsGetters.hpp
 * @brief Getters for DNS plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "dnsContext.hpp"

#include <utils/stringViewUtils.hpp>

namespace ipxp::process::dns {

inline constexpr const DNSContext& asDNSContext(const void* context) noexcept
{
	return *static_cast<const DNSContext*>(context);
}

// DNSField::DNS_ID
inline constexpr auto getDNSIdField = [](const void* context) { return asDNSContext(context).id; };

// DNSField::DNS_ANSWERS
inline constexpr auto getDNSAnswersField
	= [](const void* context) { return asDNSContext(context).answerCount; };

// DNSField::DNS_RCODE
inline constexpr auto getDNSRcodeField
	= [](const void* context) { return asDNSContext(context).responseCode; };

// DNSField::DNS_NAME
inline constexpr auto getDNSNameField
	= [](const void* context) { return toStringView(asDNSContext(context).firstQuestionName); };

// DNSField::DNS_QTYPE
inline constexpr auto getDNSQTypeField
	= [](const void* context) { return asDNSContext(context).firstQuestionType; };

// DNSField::DNS_CLASS
inline constexpr auto getDNSClassField
	= [](const void* context) { return asDNSContext(context).firstQuestionClass; };

// DNSField::DNS_RR_TTL
inline constexpr auto getDNSRRTTLField
	= [](const void* context) { return asDNSContext(context).firstResponseTimeToLive; };

// DNSField::DNS_RLENGTH
inline constexpr auto getDNSRLenghtField
	= [](const void* context) { return asDNSContext(context).firstResponseAsStringLength; };

// DNSField::DNS_RDATA
inline constexpr auto getDNSRDataField
	= [](const void* context) { return toStringView(asDNSContext(context).firstResponseAsString); };

// DNSField::DNS_PSIZE
inline constexpr auto getDNSPSizeField
	= [](const void* context) { return asDNSContext(context).firstOTPPayloadSize; };

// DNSField::DNS_DO
inline constexpr auto getDNSDoField
	= [](const void* context) { return asDNSContext(context).dnssecOkBit; };

} // namespace ipxp::process::dns