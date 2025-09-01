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

#include "flowHashData.hpp"

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

static FieldSchema createFlowHashSchema(FieldManager& fieldManager, FieldHandlers<FlowHashFields>& handlers)
{
	FieldSchema schema = fieldManager.createFieldSchema("flowHash");

	handlers.insert(FlowHashFields::FLOW_ID, schema.addScalarField(
		"FLOW_ID",
		[](const void* context) { return static_cast<const FlowHashData*>(context)->flowHash; }
	));

	return schema;
}

FlowHashPlugin::FlowHashPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createFlowHashSchema(manager, m_fieldHandlers);
}

PluginInitResult FlowHashPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	std::construct_at(reinterpret_cast<FlowHashData*>(pluginContext))->flowHash = flowContext.flowRecord.flowKey.hash();
	m_fieldHandlers[FlowHashFields::FLOW_ID].setAsAvailable(flowContext.flowRecord);

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::NoUpdateNeeded,
		.flowAction = FlowAction::NoAction,
	};
}

void FlowHashPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<FlowHashData*>(pluginContext));
}

std::string FlowHashPlugin::getName() const noexcept
{
	return flowhashPluginManifest.name; 
}

PluginDataMemoryLayout FlowHashPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(FlowHashData),
		.alignment = alignof(FlowHashData),
	};
}
static const PluginRegistrar<FlowHashPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	flowhashRegistrar(flowhashPluginManifest);

} // namespace ipxp
