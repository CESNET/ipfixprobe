/**
 * @file
 * @brief Plugin for parsing mpls traffic.
 * @author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts MPLS top label from packets,
 * stores them in per-flow plugin data, and exposes that field via FieldManager.
 * 
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "mpls.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils/spanUtils.hpp>

#include "mplsData.hpp"

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

static FieldSchema createMPLSSchema(FieldManager& fieldManager, FieldHandlers<MPLSFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("mpls");

	// TODO FIX
	/*handlers.insert(MPLSFields::MPLS_TOP_LABEL_STACK_SECTION, schema.addVectorField(
		"MPLS_TOP_LABEL_STACK_SECTION",
		[](const void* context) { return toSpan<const std::byte>(reinterpret_cast<const uint8_t*>(
				&reinterpret_cast<const MPLSData*>(context)->topLabel),
				sizeof(uint32_t)); }
	));*/

	return schema;
}

MPLSPlugin::MPLSPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createMPLSSchema(manager, m_fieldHandlers);
}

PluginInitResult MPLSPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	if (!flowContext.packet.mplsTop != 0) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	std::construct_at(reinterpret_cast<MPLSData*>(pluginContext))->topLabel = flowContext.packet.mplsTop;
	m_fieldHandlers[MPLSFields::MPLS_TOP_LABEL_STACK_SECTION].setAsAvailable(flowContext.flowRecord);
	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::NoUpdateNeeded,
		.flowAction = FlowAction::NoAction,
	};
}

void MPLSPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<MPLSData*>(pluginContext));
}

PluginDataMemoryLayout MPLSPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(MPLSData),
		.alignment = alignof(MPLSData),
	};
}

static const PluginRegistrar<MPLSPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> mplsRegistrar(mplsPluginManifest);

} // namespace ipxp
