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

	handlers.insert(MPLSFields::MPLS_TOP_LABEL_STACK_SECTION, schema.addVectorField(
		"MPLS_TOP_LABEL_STACK_SECTION",
		[](const void* context) -> std::span<const uint8_t> { return {reinterpret_cast<const uint8_t*>(
				&reinterpret_cast<const MPLSData*>(context)->topLabel),
				sizeof(uint32_t)};
		}));

	return schema;
}

MPLSPlugin::MPLSPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createMPLSSchema(manager, m_fieldHandlers);
}

PluginInitResult MPLSPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	if (!packet.mplsTopLabel.has_value()) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	std::construct_at(reinterpret_cast<MPLSData*>(pluginContext))->topLabel = *packet.mplsTopLabel;
	m_fieldHandlers[MPLSFields::MPLS_TOP_LABEL_STACK_SECTION].setAsAvailable(flowRecord);
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

std::string MPLSPlugin::getName() const noexcept
{ 
	return mplsPluginManifest.name; 
}

static const PluginRegistrar<MPLSPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> mplsRegistrar(mplsPluginManifest);

} // namespace ipxp
