/**
 * @file ipfixBuffer.cpp
 * @brief Buffer for IPFIX messages
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * IPFIX buffer for storing IPFIX messages before transmission to the collector. Sends data as is,
 * without compression.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "ipfixMessageBuilder.hpp"

#include "../ipfixRecord.hpp"
#include "../ipfixTemplate.hpp"
#include "../utils/byteUtils.hpp"
#include "ipfixMessageHeader.hpp"
#include "ipfixRecordWriter.hpp"
#include "ipfixSetHeader.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <arpa/inet.h>

namespace ipxp::output::ipfix {

IPFIXMessageBuilder::IPFIXMessageBuilder(
	const std::size_t initialSize,
	const uint32_t observationDomainId,
	utils::ByteWriter outputWriter) noexcept
	: m_observationDomainId(observationDomainId)
	, m_outputWriter(std::move(outputWriter))
{
}

void IPFIXMessageBuilder::initializeNewMessage() noexcept
{
	m_outputWriter.allocateAndWrite(
		sizeof(IPFIXMessageHeader),
		[this](std::byte* headerBuffer) -> std::size_t {
			m_messageHeader = reinterpret_cast<IPFIXMessageHeader*>(headerBuffer);
			*m_messageHeader = IPFIXMessageHeader {
				.version = htons(IPFIXMessageBuilder::CURRENT_IPFIX_VERSION),
				.length = 0,
				.exportTime = static_cast<uint32_t>(
					std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())),
				.sequenceNumber = htonl(m_sequenceNumber),
				.observationDomainId = htonl(m_observationDomainId)};
			return sizeof(IPFIXMessageHeader);
		});
}

bool IPFIXMessageBuilder::buildTemplateMessage(
	const uint16_t templateId,
	const IPFIXTemplate& ipfixTemplate) noexcept
{
	return m_outputWriter.allocateAndWrite(
		sizeof(IPFIXSetHeader) + ipfixTemplate.serializedTemplate.size(),
		[&](std::byte* buffer) -> std::size_t {
			increaseMessageLength(sizeof(IPFIXSetHeader) + ipfixTemplate.serializedTemplate.size());
			*reinterpret_cast<IPFIXSetHeader*>(buffer) = IPFIXSetHeader {
				.templateId = htons(IPFIXMessageBuilder::TEMPLATE_SET_ID),
				.length = htons(
					static_cast<uint16_t>(
						sizeof(IPFIXSetHeader) + ipfixTemplate.serializedTemplate.size()))};
			std::ranges::copy(ipfixTemplate.serializedTemplate, buffer + sizeof(IPFIXSetHeader));
			return sizeof(IPFIXSetHeader) + ipfixTemplate.serializedTemplate.size();
		});
}

bool IPFIXMessageBuilder::buildDataMessage(
	const uint16_t templateId,
	const IPFIXRecord& record) noexcept
{
	IPFIXSetHeader* setHeader = nullptr;
	const std::optional<std::size_t> bytesWritten = m_outputWriter.transactionalWrite([&]() {
		if (!m_outputWriter.allocateAndWrite(
				sizeof(IPFIXSetHeader),
				[&](std::byte* buffer) -> std::size_t {
					setHeader = reinterpret_cast<IPFIXSetHeader*>(buffer);
					*setHeader = IPFIXSetHeader {.templateId = htons(templateId), .length = 0};
					return sizeof(IPFIXSetHeader);
				})) {
			return false;
		}
		return IPFIXRecordWriter::writeRecordTo(record, m_outputWriter);
	});
	if (!bytesWritten.has_value()) {
		return false;
	}

	setHeader->length = htons(static_cast<uint16_t>(sizeof(IPFIXSetHeader) + *bytesWritten));
	increaseMessageLength(sizeof(IPFIXSetHeader) + *bytesWritten);
	return true;
}

void IPFIXMessageBuilder::reset() noexcept
{
	m_sequenceNumber = 0;
	initializeNewMessage();
}

void IPFIXMessageBuilder::increaseMessageLength(const std::size_t length) noexcept
{
	m_messageHeader->length = htons(static_cast<uint16_t>(ntohs(m_messageHeader->length) + length));
}

} // namespace ipxp::output::ipfix