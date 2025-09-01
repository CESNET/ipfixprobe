#pragma once

#include <boost/static_string.hpp>

namespace ipxp
{

struct DNSData {
	constexpr static size_t MAX_QNAME_LENGTH = 128;
	constexpr static size_t MAX_ANSWER_LENGTH = 160;

	uint16_t id;
	uint16_t answerCount;
	uint8_t responseCode;
	boost::static_string<MAX_QNAME_LENGTH> firstQuestionName;
	uint16_t firstQuestionType;
	uint16_t firstQuestionClass;
	uint32_t firstResponseTimeToLive;
	boost::static_string<MAX_ANSWER_LENGTH> firstResponseAsString;
	uint16_t firstResponseAsStringLength;
	uint16_t firstOTPPayloadSize;
	uint8_t dnssecOkBit;
};  

} // namespace ipxp

