/**
 * @file
 * @brief DNS parser class definition
 * @author Zainullin Damir <zaidamilda@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "dnsParser.hpp"

#include <functional>
#include <numeric>
#include <sstream>
#include <string>
#include <algorithm>
#include <arpa/inet.h>

#include "dnsSection.hpp"

namespace ipxp2 {

constexpr static
bool parseDnsOverTCPLength(std::span<const std::byte> payload) noexcept
{
	if (payload.size() < sizeof(uint16_t)) {
		return std::nullopt;
	}

	const uint16_t dnsDataLength 
        = ntohs(*reinterpret_cast<const uint16_t*>(payload.data()));
	if (sizeof(uint16_t) + dnsDataLength > payload.size()) {
		return std::nullopt;
	}

	return dnsDataLength;
}

constexpr
bool DnsParser::parse(
    std::span<const std::byte> payload, const bool isDnsOverTCP) noexcept
{
    const std::byte* dnsBegin = payload.data();
	if (isDnsOverTCP) {
        const std::optional<uint16_t> dnsDataLength 
            = parseDnsOverTCPLength(payload);
        if (!dnsDataLength.has_value() || 
            sizeof(uint16_t) + *dnsDataLength > payload.size()) {
			return false;
		}
        payload = payload.subspan(sizeof(uint16_t), *dnsDataLength);
        dnsBegin = payload.data();
	}

    const std::optional<DNSHeader> header = parseHeader(payload);
	if (!header.has_value()) {
		return false;
	}
    m_answersCount = ntohs(header->answerRecordCount);
    m_id = header->id;
    m_responseCode = header->flags.responseCode;

    const std::span<const std::byte> originalDNSPayload = payload;
    constexpr std::size_t questionSectionOffset = sizeof(DNSHeader);
    const std::optional<std::size_t> questionSectionSize = parseQuestionSection(
        originalDNSPayload,
        originalDNSPayload.subspan(questionSectionOffset),
        ntohs(header->questionRecordCount));
	if (!questionSectionSize.has_value()) {
		return false;
	}

    const std::size_t answerSectionOffset 
        = questionSectionOffset + *questionSectionSize;
    const std::optional<std::size_t> answerSectionSize 
        = parseAnswerSection(payload.subspan(answerSectionOffset), dnsBegin, *header);
	if (!answerSectionSize.has_value()) {
		return false;
	}

    const std::size_t authoritySectionOffset 
        = questionSectionOffset + *parseQuestionSection;
    const std::optional<std::size_t> authoritySectionSize 
        = parseAuthorityResourceRecordsSection(payload.subspan(authoritySectionOffset), dnsBegin, *header);
	if (!authoritySectionSize.has_value()) {
		return false;
	}

    const std::size_t additionalSectionOffset 
        = authoritySectionOffset + *authoritySectionSize;
    const std::optional<std::size_t> additionalSectionSize 
        = parseAdditionalResourceRecordsSection(payload.subspan(additionalSectionOffset), dnsBegin, *header);
	if (!additionalSectionSize.has_value()) {
		return false;
	}

	return true;
}

constexpr static
std::optional<DNSHeader> parseHeader(std::span<const std::byte> payload) noexcept
{
	if (payload.size() < sizeof(DNSHeader)) {
		return std::nullopt;
	}
	return *reinterpret_cast<const DNSHeader*>(payload.data());
}

constexpr
std::optional<std::size_t> DnsParser::parseQuestionSection(
    std::span<const std::byte> payload,
    const std::byte* dnsBegin, 
    const uint16_t questionCount) noexcept
{
	for (size_t questionIndex = 0; questionIndex < questionCount;
		 questionIndex++) {

		const std::optional<DNSName> name = DNSName::createFrom(payload, dnsBegin);
		if (!name.has_value()) {
			return std::nullopt;
		}
		if (name->length() + 2 * sizeof(uint16_t) > payload.size()) {
			return std::nullopt;
		}

		const uint16_t queryType = ntohs(*reinterpret_cast<const uint16_t*>(
			payload.data() + name->length()));
		const uint16_t queryClass = ntohs(*reinterpret_cast<const uint16_t*>(
			payload.data() + name->length() + sizeof(queryType)));

        payload = payload.subspan(name->length() + 2 * sizeof(uint16_t));

        if (questionIndex == 0) {
			m_parsedFirstQuestion = {ParsedQuestion {
				.name = *name,
				.type = queryType,
				.recordClass = queryClass}};
		}
	}

	return static_cast<std::size_t>(questionBegin - m_dnsData.data());
}

constexpr
std::optional<std::size_t>
DnsParser::parseAnswerSection(
    std::span<const std::byte> payload, 
    const std::byte* dnsBegin, 
    const DNSHeader& header) noexcept
{
	const std::optional<DNSSection> parsedSection 
        = DNSSection::createFrom(
            payload, dnsBegin, ntohs(header.answerRecordCount));
	if (!parsedSection.has_value()) {
		return std::nullopt;
	}

	if (!parsedSection->records.empty()) {
		m_firstAnswer = parsedSection->records[0];
	}

	return parsedSection->size;
}

constexpr
std::optional<std::size_t> 
parseAuthorityResourceRecordsSection(
    std::span<const std::byte> payload, 
    const std::byte* dnsBegin, 
    const DNSHeader& header) noexcept
{
    const std::optional<DNSSection> parsedSection 
        = DNSSection::createFrom(
            payload, dnsBegin, ntohs(header.authorityRecordCount));
	if (!parsedSection.has_value()) {
		return std::nullopt;
	}
	
	return parsedSection->size;
}

constexpr
std::optional<std::size_t> 
DnsParser::parseAdditionalResourceRecordsSection(
    std::span<const std::byte> payload, 
    const std::byte* dnsBegin, 
    const DNSHeader& header) noexcept
{
    const std::optional<DNSSection> parsedSection 
        = DNSSection::createFrom(
            payload, dnsBegin, ntohs(header.additionalRecordCount));
	if (!parsedSection.has_value()) {
        return std::nullopt;
    }

    const auto optRecord = std::ranges::find_if(
        parsedSection->records, 
        [](const ParsedRecord& record) {
            return record.type == DNS_TYPE_OPT;
        });
    if (optRecord != parsedSection->records.end()) {
        m_firstOPTRecord = ParsedOPTRecord {
            .payloadSize = optRecord->recordClass,
            .dnsSecOkBit = (optRecord->timeToLive & 0x8000) != 0};
    }

    if (header.additionalRecordCount == 0 || parsedSection->records.empty()) {
        return 0;
    }

	return parsedSection->records.back().data.end() - payload.data().begin();
}

} // namespace ipxp2

