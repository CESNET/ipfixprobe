#include "ipfixExporter.hpp"

#include "ipfixRecord.hpp"
#include "ipfixTemplateBuilder.hpp"

namespace ipxp::output::ipfix {

constexpr static bool fieldIsPresent(
	const IPFIXExporterElementsParser::ElementsMap& elementsMap,
	const process::FieldDescriptor* fieldDescriptor) noexcept
{
	return elementsMap.contains(fieldDescriptor->getGroup())
		&& elementsMap.find(fieldDescriptor->getGroup())
			   ->second.contains(std::string(fieldDescriptor->getName()));
}

constexpr static bool allFieldsPresent(
	const IPFIXExporterElementsParser::ElementsMap& elementsMap,
	const std::vector<const process::FieldDescriptor*>& fieldDescriptors) noexcept
{
	return std::ranges::all_of(
		fieldDescriptors,
		[&elementsMap](const process::FieldDescriptor* fieldDescriptor) {
			return fieldIsPresent(elementsMap, fieldDescriptor);
		});
}

void IPFIXExporter::elementMapContainsAllFields(
	const IPFIXExporterElementsParser::ElementsMap& elementsMap)
{
	const bool allElementsPresent = allFieldsPresent(elementsMap, getForwardFields())
		&& allFieldsPresent(elementsMap, getReverseFields());
	if (!allElementsPresent) {
		throw std::runtime_error(
			"Not all output fields are defined in the IPFIX exporter "
			"elements configuration file.");
	}
}

constexpr static bool isBitSet(const std::size_t value, const std::size_t bitIndex) noexcept
{
	return value & (1 << bitIndex);
}

static IPFIXTemplate createTemplate(
	const std::size_t templateIndex,
	const IPFIXExporterElementsParser::ElementsMap& elementsMap,
	const ProtocolFieldMap& protocolFields) noexcept
{
	IPFIXTemplateBuilder templateBuilder;
	templateBuilder.initializeNewTemplate(templateIndex);
	for (std::size_t protocolIndex : std::views::iota(0ULL, protocolFields.size())
			 | std::views::filter([&](const std::size_t protocolIndex) {
										 return isBitSet(templateIndex, protocolIndex);
									 })) {
		templateBuilder.addProtocol(
			protocolIndex,
			protocolFields.getFieldsOnIndex(protocolIndex)
				| std::views::transform(
					[&elementsMap](const process::FieldDescriptor* const fieldDescriptor) {
						return &elementsMap.find(fieldDescriptor->getGroup())
									->second.find(fieldDescriptor->getName())
									->second;
					})
				| std::ranges::to<std::vector<const IPFIXElement*>>());
	}

	return templateBuilder.getTemplate();
}

void IPFIXExporter::createTemplates(const IPFIXExporterElementsParser::ElementsMap& elementsMap)
{
	const std::size_t templatesCount = 1 << m_forwardProtocolFields.size();
	for (std::size_t templateIndex : std::views::iota(0ULL, templatesCount)) {
		m_templates.emplace_back(
			createTemplate(templateIndex, elementsMap, m_forwardProtocolFields));
	}
}

static std::size_t calculateTemplateIndex(
	const FlowRecord& flowRecord,
	const ProtocolFieldMap& protocolFields) noexcept
{
	std::size_t templateIndex = 0;
	for (std::size_t protocolIndex : std::views::iota(0ULL, protocolFields.size())) {
		templateIndex
			|= (std::ranges::any_of(
					protocolFields.getFieldsOnIndex(protocolIndex),
					[&](const process::FieldDescriptor* fieldDescriptor) {
						return fieldDescriptor->isInRecord(flowRecord);
					})
				<< protocolIndex);
	}
	return templateIndex;
}

void IPFIXExporter::sendUnknownTemplateToCollector(const std::size_t templateIndex) noexcept
{
	if (m_connectionOptions.mode == IPFIXExporterOptionsParser::Mode::NON_BLOCKING_TCP
		&& m_templates[templateIndex].lastSendTime != std::chrono::steady_clock::time_point {}) {
		// Template is already sent by TCP, no need to resend
		return;
	}
	if (m_connectionOptions.mode == IPFIXExporterOptionsParser::Mode::UDP
		&& std::chrono::steady_clock::now() - m_templates[templateIndex].lastSendTime
			< m_exporterOptions.templateRefreshTime) {
		// Template was sent recently by UDP, no need to resend
		return;
	}

	if (!m_dataBuffer->newSetWillFitIntoMTU(m_templates[templateIndex].serializedTemplate.size())) {
		sendBufferToCollector();
	}

	m_templates[templateIndex].lastSendTime = std::chrono::steady_clock::now();
	m_dataBuffer->appendTemplate(templateIndex, m_templates[templateIndex]);
}

void IPFIXExporter::sendBufferToCollector() noexcept
{
	if (!m_connection->isConnected()) {
		m_connection->tryToReconnect();
		m_dataBuffer->reset();
	}

	const std::span<const std::byte> transmissionBuffer = m_dataBuffer->getTransmissionBuffer();
	if (!m_connection->sendData(transmissionBuffer)) {
		m_stats.dropped++;
	} else {
		m_stats.exported++;
		m_stats.bytes += transmissionBuffer.size();
	}

	m_dataBuffer->initializeNewMessage();
}

void IPFIXExporter::writeRecordToBuffer(
	const std::size_t templateIndex,
	const ProtocolFieldMap& protocolFields,
	const FlowRecord& flowRecord)
{
	const IPFIXRecord record(protocolFields, flowRecord, m_templates[templateIndex]);
	if (!m_dataBuffer->newSetWillFitIntoMTU(record.getSize())) {
		sendBufferToCollector();
	}

	m_dataBuffer->appendRecord(templateIndex, record);
}

void IPFIXExporter::processRecord(const FlowRecord& flowRecord)
{
	const std::size_t templateIndex = calculateTemplateIndex(flowRecord, m_forwardProtocolFields);
	sendUnknownTemplateToCollector(templateIndex);
	writeRecordToBuffer(templateIndex, m_forwardProtocolFields, flowRecord);
	writeRecordToBuffer(templateIndex, m_reverseProtocolFields, flowRecord);
}

IPFIXExporter::IPFIXExporter(std::string_view params, const process::FieldManager& fieldManager)
	: OutputPlugin(fieldManager, IPFIXExporterOptionsParser(params))
	, m_forwardProtocolFields(getForwardFields())
	, m_reverseProtocolFields(getReverseFields())
{
	initializeProtocolFields();

	IPFIXExporterOptionsParser optionsParser(params);
	m_connectionOptions = optionsParser.connectionOptions;
	m_exporterOptions = optionsParser.exporterOptions;
	if (optionsParser.lz4Options.has_value()) {
		if (m_connectionOptions.mode == IPFIXExporterOptionsParser::Mode::UDP) {
			throw std::invalid_argument("LZ4 compression is not supported in UDP mode.");
		}

		m_dataBuffer = std::make_unique<IPFIXCompressBuffer>(
			IPFIXCompressBuffer::IPFIXCompressBufferConfig {
				.initialUncompressedSize = m_connectionOptions.maximalTransmissionUnit,
				.initialCompressedSize = m_connectionOptions.maximalTransmissionUnit * 3ULL},
			m_exporterOptions.observationDomainId);
	} else {
		m_dataBuffer = std::make_unique<IPFIXBuffer>(
			m_connectionOptions.maximalTransmissionUnit,
			m_exporterOptions.observationDomainId);
	}

	m_connection = std::make_optional<Connection>(
		m_connectionOptions.collector,
		m_connectionOptions.collectorPort,
		static_cast<Connection::Mode>(m_connectionOptions.mode));
}

} // namespace ipxp::output::ipfix