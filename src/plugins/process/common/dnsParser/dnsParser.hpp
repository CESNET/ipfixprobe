/**
 * @file
 * @brief DNS parser class declaration
 * @author Zainullin Damir <zaidamilda@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "dnsQuestion.hpp"
#include "dnsRecord.hpp"
#include "optRecord.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string_view>

#include <boost/container/static_vector.hpp>

namespace ipxp {

/**
 * @brief DNS parser class
 */
class DNSParser {
	constexpr static auto EMPTY_QUERY_CALLBACK = [](const DNSQuestion&) { return true; };
	constexpr static auto EMPTY_RECORD_CALLBACK = [](const DNSRecord&) { return true; };

public:
	/**
	 * @brief Parse given DNS packet
	 * @param dnsData DNS packet data
	 * @param isDnsOverTCP Flag indicating if the DNS packet is over TCP
	 * @return True of parsed successfully, false otherwise
	 */
	bool parse(
		std::span<const std::byte> payload,
		const bool isDnsOverTCP,
		const std::function<bool(const DNSQuestion& query)>& queryCallback = EMPTY_QUERY_CALLBACK,
		const std::function<bool(const DNSRecord& answer)>& answerCallback = EMPTY_RECORD_CALLBACK,
		const std::function<bool(const DNSRecord& authorityRecord)>& authorityCallback
		= EMPTY_RECORD_CALLBACK,
		const std::function<bool(const DNSRecord& additionalRecord)>& additionalCallback
		= EMPTY_RECORD_CALLBACK) noexcept;

	uint16_t answersCount;
	uint16_t id;
	uint8_t responseCode;
	std::optional<DNSQuestion> firstQuestion;
	std::optional<DNSRecord> firstAnswer;
	std::optional<OPTRecord> firstOPTRecord;
	std::span<const std::byte> fullDNSPayload;

private:
	constexpr std::optional<std::size_t> parseQuestionSection(
		std::span<const std::byte> payload,
		std::span<const std::byte> fullDNSPayload,
		const uint16_t questionCount,
		const std::function<bool(const DNSQuestion& query)>& queryCallback) noexcept;

	/*constexpr std::optional<std::size_t> parseAnswerSection(
	std::span<const std::byte> payload,
	const std::byte* dnsBegin,
	const DNSHeader& header) noexcept;

	constexpr std::optional<std::size_t> parseAuthorityResourceRecordsSection(
	std::span<const std::byte> payload,
	const std::byte* dnsBegin,
	const DNSHeader& header) noexcept;

	constexpr std::optional<std::size_t> parseAdditionalResourceRecordsSection(
	std::span<const std::byte> payload,
	const std::byte* dnsBegin,
	const DNSHeader& header) noexcept;*/
};

} // namespace ipxp
