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

#include "vlan.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>

namespace ipxp {

static const PluginManifest vlanPluginManifest = {
	.name = "vlan",
	.description = "Vlan process plugin for parsing vlan traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("vlan", "Parse VLAN traffic");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<VLANFields>> fields = {
	{VLANFields::VLAN_ID, "VLAN_ID"},
};

static FieldSchema createVLANSchema()
{
	FieldSchema schema("vlan");

	schema.addScalarField<uint16_t>(
		"VLAN_ID",
		FieldDirection::DirectionalIndifferent,
		offsetof(VLANExport, vlanId));

	return schema;
}

VLANPlugin::VLANPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createVLANSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction VLANPlugin::onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
{
	m_exportData.vlanId 
		= packet.vlanId.has_value() ? *packet.vlanId : 0;
	m_fieldHandlers[VLANFields::VLAN_ID].setAsAvailable(flowRecord);

	return FlowAction::RequestNoData;
}

ProcessPlugin* VLANPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<VLANPlugin*>(constructAtAddress), *this);
}

std::string VLANPlugin::getName() const { 
	return packetStatsPluginManifest.name; 
}

const void* VLANPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<VLANPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	vlanRegistrar(vlanPluginManifest);

} // namespace ipxp
