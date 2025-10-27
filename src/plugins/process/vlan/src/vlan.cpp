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

#include "vlanContext.hpp"
#include "vlanGetters.hpp"

#include <iostream>

#include <amon/layers/VLAN.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils.hpp>

namespace ipxp::process::vlan {

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

	handlers.insert(VLANFields::VLAN_ID, schema.addScalarField("VLAN_ID", getVLANIdField));

	return schema;
}

VLANPlugin::VLANPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createVLANSchema(manager, m_fieldHandlers);
}

OnInitResult VLANPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto vlanView = getLayerView<amon::layers::VLANView>(
		*flowContext.packetContext.packet,
		flowContext.packetContext.packet->layout.vlan);
	if (!vlanView.has_value()) {
		return OnInitResult::Irrelevant;
	}

	auto& vlanContext = *std::construct_at(reinterpret_cast<VLANContext*>(pluginContext));
	vlanContext.vlanId = vlanView->tag();
	m_fieldHandlers[VLANFields::VLAN_ID].setAsAvailable(flowContext.flowRecord);

	return OnInitResult::ConstructedFinal;
}

void VLANPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<VLANContext*>(pluginContext));
}

PluginDataMemoryLayout VLANPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(VLANContext),
		.alignment = alignof(VLANContext),
	};
}

static const PluginRegistrar<
	VLANPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	vlanRegistrar(vlanPluginManifest);

} // namespace ipxp::process::vlan
