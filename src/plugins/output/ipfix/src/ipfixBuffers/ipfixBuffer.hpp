/**
 * @file ipfixBuffer.hpp
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

#include "../ipfixRecord.hpp"
#include "../ipfixTemplate.hpp"
#include "ipfixMessageHeader.hpp"
#include "ipfixSetHeader.hpp"

#include <vector>

namespace ipxp::output::ipfix {

/**
 * @class IPFIXBuffer
 * @brief Class representing an IPFIX buffer for storing and managing IPFIX messages.
 *
 * This class provides functionality to initialize new IPFIX messages, append templates and records,
 * and manage the message length and sequence numbers. It is designed to handle uncompressed IPFIX
 * data.
 */
class IPFIXBuffer {
public:
	static constexpr inline uint16_t CURRENT_IPFIX_VERSION = 10;

	/// Set ID for sending templates
	static constexpr inline uint16_t TEMPLATE_SET_ID = 2;

	/// Maximal ethernet frame size than can be transmitted without fragmentation
	static constexpr inline int MAXIMAL_TRANSMISSION_UNIT = 1500;

	/**
	 * @brief Constructs an IPFIXBuffer with the specified initial size and observation domain ID.
	 * @param initialSize Initial size of the uncompressed data buffer.
	 * @param observationDomainId Observation domain ID for the IPFIX messages.
	 */
	IPFIXBuffer(const std::size_t initialSize, const uint32_t observationDomainId) noexcept;

	/**
	 * @brief Initializes a new IPFIX message in the buffer.
	 */
	void initializeNewMessage() noexcept;

	/**
	 * @brief Appends an IPFIX template to the buffer.
	 * @param templateId ID of the template to append.
	 * @param ipfixTemplate The IPFIX template to append.
	 */
	void appendTemplate(const uint16_t templateId, const IPFIXTemplate& ipfixTemplate) noexcept;

	/**
	 * @brief Appends an IPFIX record to the buffer.
	 * @param templateId ID of the template associated with the record.
	 * @param record The IPFIX record to append.
	 */
	void appendRecord(const uint16_t templateId, const IPFIXRecord& record) noexcept;

	/**
	 * @brief Checks if adding new set to the buffer will make possible to send it without
	 * fragmentation.
	 * @param newSetLength Length of the new set to be added.
	 * @return True if the new set will fit into the MTU, false otherwise.
	 */
	virtual bool newSetWillFitIntoMTU(const std::size_t newSetLength) const noexcept;

	/**
	 * @brief Resets the buffer to an initial state.
	 */
	virtual void reset() noexcept;

	/**
	 * @brief Gets the transmission buffer. Contains data to be sent to the collector.
	 * @return A span of bytes representing the transmission buffer.
	 */
	virtual std::span<const std::byte> getTransmissionBuffer() noexcept;

protected:
	/**
	 * @brief Calculates the new buffer length after adding new set.
	 * @param newSetLength Length of the new set to be added.
	 * @return The new buffer length.
	 */
	std::size_t newBufferLength(const std::size_t newSetLength) const noexcept;

	std::vector<std::byte> m_uncompressedData;

private:
	void increaseMessageLength(const std::size_t length) noexcept;
	void appendSetHeader(const uint16_t setId, const std::size_t setLength) noexcept;

	std::size_t m_lastSetHeaderOffset {0};
	std::size_t m_lastMessageHeaderOffset {0};
	uint32_t m_observationDomainId;
	uint32_t m_sequenceNumber {0};
};

} // namespace ipxp::output::ipfix