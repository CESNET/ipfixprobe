#pragma once

#include "ipfixTemplateManager.hpp"

#include <flowRecord.hpp>

namespace ipxp::output::ipfix {

constexpr static bool isBitSet(const std::size_t value, const std::size_t bitIndex) noexcept
{
	return value & (1 << bitIndex);
}

static std::vector<const IPFIXElement*> protocolFieldsToIPFIXElements(
	const std::size_t protocolIndex,
	const ProtocolFieldMap& protocolFields,
	const IPFIXExporterElementsParser& elementsParser) noexcept
{
	std::vector<const IPFIXElement*> ipfixElements;
	for (const process::FieldDescriptor* const fieldDescriptor :
		 protocolFields.getFieldsOnIndex(protocolIndex)) {
		ipfixElements.push_back(
			&elementsParser.getElement(fieldDescriptor->getGroup(), fieldDescriptor->getName()));
	}
	return ipfixElements;
}

static IPFIXTemplate createTemplate(
	const std::size_t templateIndex,
	const IPFIXExporterElementsParser& elementsParser,
	const ProtocolFieldMap& protocolFields) noexcept
{
	IPFIXTemplateBuilder templateBuilder;
	templateBuilder.initializeNewTemplate(templateIndex);
	for (std::size_t protocolIndex : std::views::iota(0ULL, protocolFields.getProtocolCount())) {
		if (!isBitSet(templateIndex, protocolIndex)) {
			continue;
		}

		templateBuilder.addProtocol(
			protocolIndex,
			protocolFieldsToIPFIXElements(protocolIndex, protocolFields, elementsParser));
	}

	return templateBuilder.getTemplate();
}

void IPFIXTemplateManager::createTemplates(
	const IPFIXExporterElementsParser& elementsParser,
	const ProtocolFieldMap& protocolFields)
{
	const std::size_t templatesCount = 1 << protocolFields.getProtocolCount();
	for (std::size_t templateIndex : std::views::iota(0ULL, templatesCount)) {
		m_templates.emplace_back(createTemplate(templateIndex, elementsParser, protocolFields));
	}
}

std::size_t IPFIXTemplateManager::calculateTemplateIndex(
	const FlowRecord& flowRecord,
	const ProtocolFieldMap& protocolFields) noexcept
{
	// TODO FIX
	return 666;
	/*std::size_t templateIndex = 0;
	for (std::size_t protocolIndex : std::views::iota(0ULL, protocolFields.size())) {
		templateIndex
			|= (std::ranges::any_of(
					protocolFields.getFieldsOnIndex(protocolIndex),
					[&](const process::FieldDescriptor* fieldDescriptor) {
						return fieldDescriptor->isInRecord(flowRecord);
					})
				<< protocolIndex);
	}
	return templateIndex;*/
}

} // namespace ipxp::output::ipfix