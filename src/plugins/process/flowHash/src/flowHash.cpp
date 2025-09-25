/**
 * @file
 * @brief Plugin for processing flow_hash value.
 * @author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts hashes of flows,
 * stores them in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "flowHash.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldGroup.hpp>
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

static FieldGroup createFlowHashSchema(FieldManager& fieldManager, FieldHandlers<FlowHashFields>& handlers)
{
	FieldGroup schema = fieldManager.createFieldGroup("flowHash");

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
