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
#include "ipfixBuffers/bufferTransformerFactory.hpp"
#include "ipfixBuffers/ipfixMessageBuilder.hpp"
#include "ipfixBuffers/transmissionBuffer.hpp"
#include "ipfixElements/ipfixExporterElementsParser.hpp"
#include "ipfixExporterOptionsParser.hpp"
#include "ipfixTemplate.hpp"
#include "ipfixTemplateManager.hpp"
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
	void flush() noexcept;
	void elementMapContainsAllFields(const IPFIXExporterElementsParser& elementsParser);

	void addDataMessage(const std::size_t templateIndex, const IPFIXRecord& record) noexcept;
	void addTemplateMessage(const std::size_t templateIndex) noexcept;

	IPFIXExporterOptionsParser::ConnectionOptions m_connectionOptions;
	IPFIXExporterOptionsParser::ExporterOptions m_exporterOptions;

	std::unique_ptr<IPFIXMessageBuilder> m_messageBuilder;
	std::unique_ptr<BufferTransformer> m_bufferTransformer;
	TransmissionBuffer m_transmissionBuffer;
	std::unique_ptr<Connection> m_connection;
	std::optional<IPFIXTemplateManager> m_templateManager;

	ProtocolFieldMap m_forwardProtocolFields;
	ProtocolFieldMap m_reverseProtocolFields;
	// uint32_t m_sequenceNumber {0};
	// FieldsBitset m_activeFieldsMask;
};

} // namespace ipxp::output::ipfix