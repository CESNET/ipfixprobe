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
class IPFIXMessageBuilder {
public:
	static constexpr inline uint16_t CURRENT_IPFIX_VERSION = 10;

	/// Set ID for sending templates
	static constexpr inline uint16_t TEMPLATE_SET_ID = 2;

	/// Maximal ethernet frame size than can be transmitted without fragmentation
	static constexpr inline int MAXIMAL_TRANSMISSION_UNIT = 1500;

	/**
	 * @brief Constructs an IPFIXMessageBuilder with the specified initial size and observation
	 * domain ID.
	 * @param initialSize Initial size of the uncompressed data buffer.
	 * @param observationDomainId Observation domain ID for the IPFIX messages.
	 */
	IPFIXMessageBuilder(
		const std::size_t initialSize,
		const uint32_t observationDomainId,
		utils::ByteWriter outputWriter) noexcept;

	/**
	 * @brief Builds an IPFIX template message in the buffer.
	 * @param templateId ID of the template to build.
	 * @param ipfixTemplate The IPFIX template to build.
	 */
	bool
	buildTemplateMessage(const uint16_t templateId, const IPFIXTemplate& ipfixTemplate) noexcept;

	/**
	 * @brief Appends an IPFIX record to the buffer.
	 * @param templateId ID of the template associated with the record.
	 * @param record The IPFIX record to append.
	 */
	bool buildDataMessage(const uint16_t templateId, const IPFIXRecord& record) noexcept;

	/**
	 * @brief Resets the buffer to an initial state.
	 */
	void reset() noexcept;

	/**
	 * @brief Initializes a new IPFIX message in the buffer.
	 */
	void initializeNewMessage() noexcept;

private:
	void increaseMessageLength(const std::size_t length) noexcept;

	std::size_t m_lastSetHeaderOffset {0};
	std::size_t m_lastMessageHeaderOffset {0};
	uint32_t m_observationDomainId;
	uint32_t m_sequenceNumber {0};
	utils::ByteWriter m_outputWriter;
	IPFIXMessageHeader* m_messageHeader {nullptr};
};

} // namespace ipxp::output::ipfix