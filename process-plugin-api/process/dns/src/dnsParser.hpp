/**
 * @file
 * @brief DNS parser class declaration
 * @author Zainullin Damir <zaidamilda@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <boost/container/static_vector.hpp>

#include "dnsRecord.hpp"
#include "dnsQuestion.hpp"
#include "optRecord.hpp"

namespace ipxp2 {

/**
 * @brief DNS parser class
 */
class DnsParser {

public:
	/**
	 * @brief Parse given DNS packet
	 * @param dnsData DNS packet data
	 * @param isDnsOverTCP Flag indicating if the DNS packet is over TCP
	 * @return True of parsed successfully, false otherwise
	 */
	constexpr bool parse(
    std::span<const std::byte> payload, const bool isDnsOverTCP) noexcept;

    uint16_t answersCount;
    uint16_t id;
    uint8_t responseCode;
    std::optional<DNSQuestion> firstQuestion;
	std::optional<DNSRecord> firstAnswer;
	std::optional<OPTRecord> firstOPTRecord;
    const std::byte* dnsBegin;
    

private:

	constexpr std::optional<std::size_t> parseQuestionSection(
    std::span<const std::byte> payload,
    const std::byte* dnsBegin, 
    const uint16_t questionCount) noexcept;

    constexpr std::optional<std::size_t> parseAnswerSection(
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
    const DNSHeader& header) noexcept;

};

} // namespace ipxp2

