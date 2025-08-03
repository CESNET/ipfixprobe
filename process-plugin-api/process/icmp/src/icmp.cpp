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

#include "icmp.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

namespace ipxp {


static const PluginManifest icmpPluginManifest = {
	.name = "icmp",
	.description = "ICMP process plugin for parsing icmp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("icmp", "Parse ICMP traffic");
			parser.usage(std::cout);*/
		},
};


const inline std::vector<FieldPair<ICMPFields>> fields = {
	{ICMPFields::L4_ICMP_TYPE_CODE, "L4_ICMP_TYPE_CODE"},
};

static FieldSchema createICMPSchema()
{
	FieldSchema schema("icmp");

	schema.addScalarField<uint16_t>(
		"L4_ICMP_TYPE_CODE",
		FieldDirection::DirectionalIndifferent,
		offsetof(ICMPExport, typeCode));

	return schema;
}

ICMPPlugin::ICMPPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createICMPSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction ICMPPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	// TODO :
	// values from dissector enums
	constexpr uint16_t ICMP_PROTO = 1;
	constexpr uint16_t ICMPV6_PROTO = 58;

	if (packet.flowKey.l4Protocol == ICMP_PROTO || packet.flowKey.l4Protocol == ICMPV6_PROTO) {
		if (packet.payload.size() < sizeof(ICMPExport::typeCode)) {
			return FlowAction::RequestNoData;
		}

		// the type and code are the first two bytes, type on MSB and code on LSB
		// in the network byte order
		m_exportData.typeCode = *reinterpret_cast<const uint16_t*>(packet.payload.data());
		m_fieldHandlers[ICMPFields::L4_ICMP_TYPE_CODE].setAsAvailable(flowRecord);
	}

	return FlowAction::RequestNoData;
}

ProcessPlugin* ICMPPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<ICMPPlugin*>(constructAtAddress), *this);
}

std::string ICMPPlugin::getName() const { 
	return icmpPluginManifest.name; 
}

const void* ICMPPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<ICMPPlugin, 
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> icmpRegistrar(icmpPluginManifest);

} // namespace ipxp
