/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "idpContent.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

namespace ipxp {

static const PluginManifest idpcontentPluginManifest = {
	.name = "idpcontent",
	.description = "Idpcontent process plugin for parsing idpcontent traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("idpcontent", "Parse first bytes of flow payload");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<IDPContentFields>> fields = {
	{IDPContentFields::IDP_CONTENT, "IDP_CONTENT"},
	{IDPContentFields::IDP_CONTENT_REV, "IDP_CONTENT_REV"},
};

static FieldSchema createIDPContentSchema()
{
	FieldSchema schema("bstats");

	schema.addVectorField<uint8_t>(
		"IDP_CONTENT",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint8_t> {
			return {reinterpret_cast<const uint8_t*>(
						reinterpret_cast<const IDPContentExport*>(thisPtr)
							->directionalContent[Direction::Forward]->data()),
				static_cast<std::size_t>(
					reinterpret_cast<const IDPContentExport*>(thisPtr)
						->directionalContent[Direction::Forward]->size())};
		});

	schema.addVectorField<uint8_t>(
		"IDP_CONTENT_REV",
		FieldDirection::Reverse,
		[](const void* thisPtr) -> std::span<const uint8_t> {
			return {reinterpret_cast<const uint8_t*>(
						reinterpret_cast<const IDPContentExport*>(thisPtr)
							->directionalContent[Direction::Reverse]->data()),
				static_cast<std::size_t>(
					reinterpret_cast<const IDPContentExport*>(thisPtr)
						->directionalContent[Direction::Reverse]->size())};
		});

	schema.addBiflowPair("IDP_CONTENT", "IDP_CONTENT_REV");

	return schema;
}

IDPContentPlugin::IDPContentPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createIDPContentSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction IDPContentPlugin::updateContent(FlowRecord& flowRecord, const Packet& packet) noexcept
{
	// Check zero-packets and be sure, that the exported content is from both directions
	if (m_exportData.directionalContent[packet.direction].has_value()) {
		return m_exportData.directionalContent[static_cast<Direction>(!packet.direction)].has_value()
			? FlowAction::RequestNoData
			: FlowAction::RequestTrimmedData;
	}

	if (packet.payload.empty()) {
		return FlowAction::RequestTrimmedData;
	}

	const std::size_t sizeToSave = std::min(IDPContentExport::MAX_CONTENT_LENGTH, 
                              packet.payload.size());
	m_exportData.directionalContent[packet.direction] 
		= std::make_optional<IDPContentExport::Content>(
			packet.payload.data(), packet.payload.data() + sizeToSave);
	m_fieldHandlers[fields[packet.direction].first].setAsAvailable(flowRecord);
}

FlowAction IDPContentPlugin::onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
{
	return updateContent(flowRecord, packet);
}

FlowAction IDPContentPlugin::onFlowUpdate(FlowRecord& flowRecord, const Packet& packet)
{
	return updateContent(flowRecord, packet);
}

ProcessPlugin* IDPContentPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<IDPContentPlugin*>(constructAtAddress), *this);
}

std::string IDPContentPlugin::getName() const { 
	return idpcontentPluginManifest.name; 
}

const void* IDPContentPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<IDPContentPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	idpcontentRegistrar(idpcontentPluginManifest);

} // namespace ipxp
