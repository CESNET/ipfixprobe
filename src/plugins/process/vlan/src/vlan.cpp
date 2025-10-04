/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses VLAN traffic,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "vlan.hpp"

#include "vlanData.hpp"

#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils.hpp>

namespace ipxp {

static const PluginManifest vlanPluginManifest = {
	.name = "vlan",
	.description = "Vlan process plugin for parsing vlan traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("vlan", "Parse VLAN traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createVLANSchema(FieldManager& fieldManager, FieldHandlers<VLANFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("vlan");

	handlers.insert(VLANFields::VLAN_ID, schema.addScalarField("VLAN_ID", [](const void* context) {
		return reinterpret_cast<const VLANData*>(context)->vlanId;
	}));

	return schema;
}

VLANPlugin::VLANPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createVLANSchema(manager, m_fieldHandlers);
}

PluginInitResult VLANPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	std::construct_at(reinterpret_cast<VLANData*>(pluginContext))->vlanId
		= flowContext.packet.vlan_id;
	m_fieldHandlers[VLANFields::VLAN_ID].setAsAvailable(flowContext.flowRecord);

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::NoUpdateNeeded,
		.flowAction = FlowAction::NoAction,
	};
}

void VLANPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<VLANData*>(pluginContext));
}

PluginDataMemoryLayout VLANPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(VLANData),
		.alignment = alignof(VLANData),
	};
}

static const PluginRegistrar<
	VLANPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	vlanRegistrar(vlanPluginManifest);

} // namespace ipxp
