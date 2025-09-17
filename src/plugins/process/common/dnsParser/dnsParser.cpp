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
#include "dnsSectionReader.hpp"
#include "dnsHeader.hpp"

namespace ipxp {

constexpr static
std::optional<std::size_t> parseDNSOverTCPLength(std::span<const std::byte> payload) noexcept
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

static
std::optional<std::size_t>
parseSection(
    std::span<const std::byte> payload, 
    std::span<const std::byte> fullDNSPayload, 
    const uint16_t recordCount,
    const std::function<bool(const DNSRecord& record)>& recordCallback) noexcept
{
    std::size_t sectionSize{0};
    const auto sectionBegin = payload.begin();

    DNSSectionReader reader;
    
    std::ranges::for_each(
        reader.getRange(recordCount, payload, fullDNSPayload), 
        [&, needToCallCallback = true]
        (const DNSRecord& record) mutable {
            sectionSize = static_cast<std::size_t>(
                std::distance(sectionBegin, record.payload.getSpan().end()));
            if (needToCallCallback) {
                needToCallCallback = !recordCallback(record);
            }
    });

	/*if (!parsedSection->records.empty()) {
		m_firstAnswer = parsedSection->records[0];
	}*/

	return sectionSize;
}

constexpr static
std::optional<DNSHeader> parseHeader(std::span<const std::byte> payload) noexcept
{
	if (payload.size() < sizeof(DNSHeader)) {
		return std::nullopt;
	}
	return *reinterpret_cast<const DNSHeader*>(payload.data());
}

bool DNSParser::parse(
    std::span<const std::byte> payload, const bool isDNSOverTCP,
    const std::function<bool(const DNSQuestion& query)>& queryCallback,
    const std::function<bool(const DNSRecord& answer)>& answerCallback,
    const std::function<bool(const DNSRecord& authorityRecord)>& authorityCallback,
    const std::function<bool(const DNSRecord& additionalRecord)>& additionalCallback
) noexcept
{
	if (isDNSOverTCP) {
        const std::optional<uint16_t> dnsDataLength 
            = parseDNSOverTCPLength(payload);
        if (!dnsDataLength.has_value() || 
            sizeof(uint16_t) + *dnsDataLength > payload.size()) {
			return false;
		}
        payload = payload.subspan(sizeof(uint16_t), *dnsDataLength);
        
	}

    fullDNSPayload = payload;
    
    const std::optional<DNSHeader> header = parseHeader(payload);
	if (!header.has_value()) {
		return false;
	}
    answersCount = ntohs(header->answerRecordCount);
    id = header->id;
    responseCode = header->flags.responseCode;

    constexpr std::size_t questionSectionOffset = sizeof(DNSHeader);
    const std::optional<std::size_t> questionSectionSize = parseQuestionSection(
        payload.subspan(questionSectionOffset),
        fullDNSPayload,
        ntohs(header->questionRecordCount),
        queryCallback);
	if (!questionSectionSize.has_value()) {
		return false;
	}

    const std::size_t answerSectionOffset 
        = questionSectionOffset + *questionSectionSize;
    const std::optional<std::size_t> answerSectionSize 
        = parseSection(
            payload.subspan(answerSectionOffset), 
            fullDNSPayload, 
            ntohs(header->answerRecordCount),
            answerCallback);
	if (!answerSectionSize.has_value()) {
		return false;
	}

    const std::size_t authoritySectionOffset 
        = questionSectionOffset + *questionSectionSize;
    const std::optional<std::size_t> authoritySectionSize 
        = parseSection(
            payload.subspan(authoritySectionOffset), 
            fullDNSPayload, 
            ntohs(header->authorityRecordCount),
            authorityCallback);
	if (!authoritySectionSize.has_value()) {
		return false;
	}

    const std::size_t additionalSectionOffset 
        = authoritySectionOffset + *authoritySectionSize;
    const std::optional<std::size_t> additionalSectionSize 
        = parseSection(
            payload.subspan(additionalSectionOffset), 
            fullDNSPayload, 
            ntohs(header->additionalRecordCount),
            additionalCallback);
	if (!additionalSectionSize.has_value()) {
		return false;
	}

	return true;
}

constexpr
std::optional<std::size_t> DNSParser::parseQuestionSection(
    std::span<const std::byte> payload,
    std::span<const std::byte> fullDNSPayload, 
    const uint16_t questionCount,
    const std::function<bool(const DNSQuestion& query)>& queryCallback) noexcept
{
    const std::byte* queriesBegin = payload.data();
    bool needToCallCallback = true;

	for (size_t questionIndex = 0; questionIndex < questionCount; questionIndex++) {

		const std::optional<DNSName> name 
            = DNSName::createFrom(payload, fullDNSPayload);
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

        if (needToCallCallback) {
            needToCallCallback = !queryCallback(
                DNSQuestion{
                    .name = *name,
                    .type = static_cast<DNSQueryType>(queryType),
                    .recordClass = queryClass
            });
        }
    }
        /*if (questionIndex == 0) {
            m_parsedFirstQuestion = {ParsedQuestion {
                .name = *name,
                .type = queryType,
            .recordClass = queryClass}};
        }*/

	return static_cast<std::size_t>(payload.data() - queriesBegin);
}
/*
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
}*/

} // namespace ipxp

