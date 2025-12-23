/**
 * @file ipfixTemplateBuilder.hpp
 * @brief Class that implements a factory for IPFIX templates.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "ipfixElements/ipfixElement.hpp"
#include "utils/byteUtils.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

#include <arpa/inet.h>

namespace ipxp::output::ipfix {

/**
 * @class IPFIXTemplateBuilder
 * @brief Class for building IPFIX templates.
 *
 * This class provides functionality to initialize a new IPFIX template, add protocol fields,
 * and retrieve the constructed template.
 */
class IPFIXTemplateBuilder {
public:
	/**
	 * @brief Initializes a new IPFIX template with the given template ID.
	 * @param templateId The ID of the template to initialize.
	 * @throws std::runtime_error if the template builder is already initialized.
	 */
	void initializeNewTemplate(const uint16_t templateId)
	{
		if (m_initialized) {
			throw std::runtime_error("IPFIX template is already initialized.");
		}

		m_initialized = true;
		m_fieldCount = 0;
		m_staticSize = 0;
		m_serializationBuffer.clear();
		m_protocolIndices.clear();

		utils::appendBytes(m_serializationBuffer, htons(templateId));
		// Placeholder for field count
		utils::appendBytes(m_serializationBuffer, uint16_t {0});
	}

	/**
	 * @brief Adds a protocol and its associated fields to the IPFIX template.
	 * @param protocolIndex The index of the protocol.
	 * @param protocolFields A vector of pointers to the IPFIX elements representing the protocol
	 * fields.
	 */
	void
	addProtocol(const uint8_t protocolIndex, const std::vector<const IPFIXElement*>& protocolFields)
	{
		m_protocolIndices.push_back(protocolIndex);
		for (const IPFIXElement* field : protocolFields) {
			addField(*field);
		}
	}

	/**
	 * @brief Retrieves the constructed IPFIX template.
	 * @return The constructed IPFIX template.
	 * @throws std::runtime_error if the template builder is not initialized.
	 */
	IPFIXTemplate getTemplate()
	{
		if (!m_initialized) {
			throw std::runtime_error("IPFIX template is not initialized.");
		}
		m_initialized = false;

		*reinterpret_cast<uint16_t*>(m_serializationBuffer.data() + sizeof(uint16_t))
			= htons(m_fieldCount);
		return {std::move(m_serializationBuffer), std::move(m_protocolIndices), m_staticSize};
	}

private:
	void addField(const IPFIXElement& field) noexcept
	{
		if (field.length != IPFIXElement::VARIABLE_LENGTH) {
			m_staticSize += field.length;
		}

		const uint16_t fieldId = field.pen != 0 ? (0x8000 | field.id) : field.id;
		utils::appendBytes<uint16_t>(m_serializationBuffer, htons(fieldId));
		utils::appendBytes<uint16_t>(m_serializationBuffer, htons(field.length));
		if (field.pen != 0) {
			utils::appendBytes<uint32_t>(m_serializationBuffer, htonl(field.pen));
		}
		m_fieldCount++;
	}

	bool m_initialized {false};
	std::vector<std::byte> m_serializationBuffer;
	std::vector<uint8_t> m_protocolIndices;
	uint16_t m_fieldCount {0};
	uint16_t m_staticSize {0};
};

} // namespace ipxp::output::ipfix