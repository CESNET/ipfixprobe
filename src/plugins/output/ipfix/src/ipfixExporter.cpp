#include "ipfixExporter.hpp"

#include "ipfixRecord.hpp"
#include "ipfixTemplateBuilder.hpp"

namespace ipxp::output::ipfix {

constexpr static bool fieldIsPresent(
	const IPFIXExporterElementsParser& elementsParser,
	const process::FieldDescriptor* fieldDescriptor) noexcept
{
	return elementsParser.hasElement(fieldDescriptor->getGroup(), fieldDescriptor->getName());
}

constexpr static bool allFieldsPresent(
	const IPFIXExporterElementsParser& elementsParser,
	const std::vector<const process::FieldDescriptor*>& fieldDescriptors) noexcept
{
	return std::ranges::all_of(
		fieldDescriptors,
		[&elementsParser](const process::FieldDescriptor* fieldDescriptor) {
			return fieldIsPresent(elementsParser, fieldDescriptor);
		});
}

void IPFIXExporter::elementMapContainsAllFields(const IPFIXExporterElementsParser& elementsParser)
{
	const bool allElementsPresent = allFieldsPresent(elementsParser, getForwardFields())
		&& allFieldsPresent(elementsParser, getReverseFields());
	if (!allElementsPresent) {
		throw std::runtime_error(
			"Not all output fields are defined in the IPFIX exporter "
			"elements configuration file.");
	}
}

void IPFIXExporter::addTemplateMessage(const std::size_t templateIndex) noexcept
{
	const bool success = m_messageBuilder->buildTemplateMessage(
							 templateIndex,
							 m_templateManager->getTemplate(templateIndex))
		&& m_bufferTransformer->transformBuffer();
	if (success) {
		return;
	}

	flush();
	m_messageBuilder->buildTemplateMessage(
		templateIndex,
		m_templateManager->getTemplate(templateIndex));
	m_bufferTransformer->transformBuffer();
}

void IPFIXExporter::addDataMessage(
	const std::size_t templateIndex,
	const IPFIXRecord& record) noexcept
{
	const bool success = m_messageBuilder->buildDataMessage(templateIndex, record)
		&& m_bufferTransformer->transformBuffer();
	if (success) {
		return;
	}

	flush();
	m_messageBuilder->buildDataMessage(templateIndex, record);
	m_bufferTransformer->transformBuffer();
}

void IPFIXExporter::flush() noexcept
{
	const Connection::SendStatus status = m_connection->sendData(m_transmissionBuffer.getData());
	switch (status) {
	case Connection::SendStatus::FAILURE:
		// dropped++
		return;
	case Connection::SendStatus::RECONNECTED:
		m_transmissionBuffer.reset();
		m_bufferTransformer->reset();
		return;
	case Connection::SendStatus::SUCCESS:
		// sent++
		return;
	}
}

void IPFIXExporter::processRecord(const FlowRecord& flowRecord)
{
	const std::size_t templateIndex
		= IPFIXTemplateManager::calculateTemplateIndex(flowRecord, m_forwardProtocolFields);
	if (m_templateManager->templateNeedsRefresh(templateIndex)) {
		m_templateManager->onTemplateSent(templateIndex);
		addTemplateMessage(templateIndex);
	}

	// TODO FIX
	addDataMessage(
		templateIndex,
		IPFIXRecord(
			m_forwardProtocolFields,
			flowRecord,
			m_templateManager->getTemplate(templateIndex)));
	addDataMessage(
		templateIndex,
		IPFIXRecord(
			m_reverseProtocolFields,
			flowRecord,
			m_templateManager->getTemplate(templateIndex)));
}

IPFIXExporter::IPFIXExporter(std::string_view params, const process::FieldManager& fieldManager)
	: OutputPlugin(fieldManager, IPFIXExporterOptionsParser(params))
	, m_forwardProtocolFields(getForwardFields())
	, m_reverseProtocolFields(getReverseFields())
{
	IPFIXExporterOptionsParser optionsParser(params);
	m_connectionOptions = optionsParser.connectionOptions;
	m_exporterOptions = optionsParser.exporterOptions;

	const BufferTransformerFactory::BufferTransformationType transformatorType
		= optionsParser.lz4Options.has_value()
		? BufferTransformerFactory::BufferTransformationType::LZ4
		: BufferTransformerFactory::BufferTransformationType::Identity;
	if (transformatorType == BufferTransformerFactory::BufferTransformationType::LZ4
		&& m_connectionOptions.mode == ConnectionFactory::Mode::UDP) {
		throw std::invalid_argument("LZ4 compression is not supported in UDP mode.");
	}
	m_bufferTransformer = BufferTransformerFactory::createTransformer(
		transformatorType,
		m_transmissionBuffer.getWriter());

	m_messageBuilder = std::make_unique<IPFIXMessageBuilder>(
		m_connectionOptions.maximalTransmissionUnit,
		m_exporterOptions.observationDomainId,
		m_bufferTransformer->getWriter());

	m_connection = ConnectionFactory::createConnection(
		m_connectionOptions.mode,
		m_connectionOptions.collector,
		m_connectionOptions.collectorPort);
}

} // namespace ipxp::output::ipfix