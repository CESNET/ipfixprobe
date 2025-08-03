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

#include "flowHash.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

namespace ipxp {

static const PluginManifest flowhashPluginManifest = {
	.name = "flowhash",
	.description = "flowhash process plugin for parsing flowhash value.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("flowhash", "Export flow hash as flow id");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<FlowHashFields>> fields = {
	{FlowHashFields::FLOW_ID, "FLOW_ID"},
};


static FieldSchema createFlowHashSchema()
{
	FieldSchema schema("flowHash");

	schema.addScalarField<uint64_t>(
		"FLOW_ID",
		FieldDirection::DirectionalIndifferent,
		offsetof(FlowHashExport, flowHash));

	return schema;
}

FlowHashPlugin::FlowHashPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createFlowHashSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction FlowHashPlugin::onFlowCreate(
	FlowRecord& flowRecord, [[maybe_unused]]const Packet& packet)
{
	m_exportData.flowHash = flowRecord.flowKey.hash();
	m_fieldHandlers[FlowHashFields::FLOW_ID].setAsAvailable(flowRecord);

	return FlowAction::RequestNoData;
}

ProcessPlugin* FlowHashPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<FlowHashPlugin*>(constructAtAddress), *this);
}

std::string FlowHashPlugin::getName() const { 
	return flowhashPluginManifest.name; 
}

const void* FlowHashPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<FlowHashPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	flowhashRegistrar(flowhashPluginManifest);

} // namespace ipxp
