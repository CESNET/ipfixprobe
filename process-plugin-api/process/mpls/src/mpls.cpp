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

#include "mpls.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

namespace ipxp {

static const PluginManifest mplsPluginManifest = {
	.name = "mpls",
	.description = "Mpls process plugin for parsing mpls traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("mpls", "Parse MPLS traffic");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<MPLSFields>> fields = {
	{MPLSFields::MPLS_TOP_LABEL_STACK_SECTION, "MPLS_TOP_LABEL_STACK_SECTION"},
};

static FieldSchema createMPLSSchema()
{
	FieldSchema schema("mpls");

	schema.addVectorField<uint8_t>(
		"MPLS_TOP_LABEL_STACK_SECTION",
		FieldDirection::DirectionalIndifferent,
		[](const void* thisPtr) -> std::span<const uint8_t> {
			return {reinterpret_cast<const uint8_t*>(
				&reinterpret_cast<const MPLSExport*>(thisPtr)->topLabel), 
				sizeof(uint32_t)};
		});

	return schema;
}

MPLSPlugin::MPLSPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createMPLSSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction MPLSPlugin::onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
{
	if (!packet.mplsTopLabel.has_value()) {
		return FlowAction::RequestNoData;
	}

	m_exportData.topLabel = *packet.mplsTopLabel;
	m_fieldHandlers[MPLSFields::MPLS_TOP_LABEL_STACK_SECTION].setAsAvailable(flowRecord);

	return FlowAction::RequestNoData;
}

ProcessPlugin* MPLSPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<MPLSPlugin*>(constructAtAddress), *this);
}

std::string MPLSPlugin::getName() const { 
	return mplsPluginManifest.name; 
}

const void* MPLSPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<MPLSPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> mplsRegistrar(mplsPluginManifest);

} // namespace ipxp
