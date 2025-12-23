/**
 * @file ipfixExporter.hpp
 * @brief IPFIX exporter plugin declaration.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * IPFIX exporter plugin for exporting flow records in IPFIX format to the collector.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "connection.hpp"
#include "ipfixBuffers/ipfixBuffer.hpp"
#include "ipfixBuffers/ipfixCompressBuffer.hpp"
#include "ipfixElements/ipfixExporterElementsParser.hpp"
#include "ipfixExporterOptionsParser.hpp"
#include "ipfixTemplate.hpp"
#include "protocolFieldMap.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <ipfixprobe/outputPlugin/outputPlugin.hpp>

namespace ipxp::output::ipfix {

/**
 * @class IPFIXExporter
 * @brief IPFIX exporter plugin. Automatically handles connection and export buffer management.
 */
class IPFIXExporter : public OutputPlugin {
public:
	/**
	 * @brief Constructs an IPFIXExporter with the given parameters and field manager.
	 * @param params Configuration parameters for the exporter.
	 * @param fieldManager The field manager to use for field handling.
	 */
	IPFIXExporter(std::string_view params, const process::FieldManager& fieldManager);

	/**
	 * @brief Processes a flow record for export.
	 * @param flowRecord The flow record to be processed.
	 */
	void processRecord(const FlowRecord& flowRecord) override;

private:
	void createTemplates(const IPFIXExporterElementsParser::ElementsMap& elementsMap);
	void appendTemplateMessageToBuffer(const uint16_t templateId) noexcept;
	void elementMapContainsAllFields(const IPFIXExporterElementsParser::ElementsMap& elementsMap);
	void initializeProtocolFields();
	void sendUnknownTemplateToCollector(const std::size_t templateIndex) noexcept;
	void sendBufferToCollector() noexcept;
	void writeRecordToBuffer(
		const std::size_t templateIndex,
		const ProtocolFieldMap& protocolFields,
		const FlowRecord& flowRecord);

	std::vector<IPFIXTemplate> m_templates;
	std::unique_ptr<IPFIXBuffer> m_dataBuffer;
	ProtocolFieldMap m_forwardProtocolFields;
	ProtocolFieldMap m_reverseProtocolFields;
	IPFIXExporterOptionsParser::ConnectionOptions m_connectionOptions;
	IPFIXExporterOptionsParser::ExporterOptions m_exporterOptions;
	uint32_t m_sequenceNumber {0};
	FieldsBitset m_activeFieldsMask;
	std::optional<Connection> m_connection;
};

} // namespace ipxp::output::ipfix