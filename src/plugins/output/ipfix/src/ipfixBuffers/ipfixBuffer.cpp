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

#include "ipfixBuffer.hpp"

#include "../ipfixRecord.hpp"
#include "../ipfixTemplate.hpp"
#include "../utils/byteUtils.hpp"
#include "ipfixMessageHeader.hpp"
#include "ipfixSetHeader.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <arpa/inet.h>

namespace ipxp::output::ipfix {

IPFIXBuffer::IPFIXBuffer(const std::size_t initialSize, const uint32_t observationDomainId) noexcept
	: m_observationDomainId(observationDomainId)
{
	m_uncompressedData.reserve(initialSize);
}

void IPFIXBuffer::initializeNewMessage() noexcept
{
	m_lastMessageHeaderOffset = m_uncompressedData.size();
	m_uncompressedData.resize(m_uncompressedData.size() + sizeof(IPFIXMessageHeader));
	*reinterpret_cast<IPFIXMessageHeader*>(m_uncompressedData.data() + m_lastMessageHeaderOffset)
		= IPFIXMessageHeader {
			.version = htons(IPFIXBuffer::CURRENT_IPFIX_VERSION),
			.length = 0,
			.exportTime = static_cast<uint32_t>(
				std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())),
			.sequenceNumber = htonl(m_sequenceNumber),
			.observationDomainId = htonl(m_observationDomainId)};
}

void IPFIXBuffer::appendTemplate(
	const uint16_t templateId,
	const IPFIXTemplate& ipfixTemplate) noexcept
{
	appendSetHeader(IPFIXBuffer::TEMPLATE_SET_ID, ipfixTemplate.serializedTemplate.size());
	m_uncompressedData.insert(
		m_uncompressedData.end(),
		ipfixTemplate.serializedTemplate.begin(),
		ipfixTemplate.serializedTemplate.end());
	// increaseMessageLength(ipfixTemplate.serializedTemplate.size());
}

void IPFIXBuffer::appendRecord(const uint16_t templateId, const IPFIXRecord& record) noexcept
{
	appendSetHeader(templateId, record.getSize());
	utils::ByteWriter outputWriter = utils::ByteWriter::makeByteWriter(m_uncompressedData);
	record.writeTo(outputWriter);
}

bool IPFIXBuffer::newSetWillFitIntoMTU(const std::size_t newSetLength) const noexcept
{
	return newBufferLength(newSetLength) <= MAXIMAL_TRANSMISSION_UNIT;
}

void IPFIXBuffer::reset() noexcept
{
	m_sequenceNumber = 0;
	reinterpret_cast<IPFIXMessageHeader*>(m_uncompressedData.data())->sequenceNumber = 0;
	m_uncompressedData.clear();
}

std::span<const std::byte> IPFIXBuffer::getTransmissionBuffer() noexcept
{
	return std::span<const std::byte>(m_uncompressedData.data(), m_uncompressedData.size());
}

std::size_t IPFIXBuffer::newBufferLength(const std::size_t newSetLength) const noexcept
{
	if (m_uncompressedData.empty()) {
		return m_uncompressedData.size() + sizeof(IPFIXMessageHeader) + sizeof(IPFIXSetHeader)
			+ newSetLength;
	}

	return m_uncompressedData.size() + sizeof(IPFIXMessageHeader) + newSetLength;
}

void IPFIXBuffer::increaseMessageLength(const std::size_t length) noexcept
{
	auto& messageHeader = *reinterpret_cast<IPFIXMessageHeader*>(
		m_uncompressedData.data() + m_lastMessageHeaderOffset);
	messageHeader.length = htons(static_cast<uint16_t>(ntohs(messageHeader.length) + length));
}

void IPFIXBuffer::appendSetHeader(const uint16_t setId, const std::size_t setLength) noexcept
{
	increaseMessageLength(setLength + sizeof(IPFIXSetHeader));
	m_lastSetHeaderOffset = m_uncompressedData.size();
	m_uncompressedData.resize(m_uncompressedData.size() + sizeof(IPFIXSetHeader));

	*reinterpret_cast<IPFIXSetHeader*>(m_uncompressedData.data() + m_lastSetHeaderOffset)
		= IPFIXSetHeader {
			.templateId = htons(setId),
			.length = htons(static_cast<uint16_t>(setLength + sizeof(IPFIXSetHeader)))};
}

} // namespace ipxp::output::ipfix