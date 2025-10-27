/**
 * @file
 * @brief Export data of DNS plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <boost/static_string.hpp>

namespace ipxp::process::dns {

/**
 * @class DNSContext
 * @brief Class representing DNS data.
 *
 * Contains request and response strings, as well as id, answer count, response code,
 * question type, question class, response TTL, response length, OTP payload size
 * and DNSSEC OK bit.
 */
struct DNSContext {
	constexpr static size_t MAX_QNAME_LENGTH = 128;
	boost::static_string<MAX_QNAME_LENGTH> firstQuestionName;

	constexpr static size_t MAX_ANSWER_LENGTH = 160;
	boost::static_string<MAX_ANSWER_LENGTH> firstResponseAsString;

	uint16_t id;
	uint16_t answerCount;
	uint8_t responseCode;
	uint16_t firstQuestionType;
	uint16_t firstQuestionClass;
	uint32_t firstResponseTimeToLive;
	uint16_t firstResponseAsStringLength;
	uint16_t firstOTPPayloadSize;
	uint8_t dnssecOkBit;
};

} // namespace ipxp::process::dns
