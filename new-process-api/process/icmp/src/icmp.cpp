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

#include "icmpData.hpp"

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

static FieldSchema createICMPSchema(FieldManager& fieldManager, FieldHandlers<ICMPFields>& handlers)
{
	FieldSchema schema = fieldManager.createFieldSchema("icmp");
	handlers.insert(ICMPFields::L4_ICMP_TYPE_CODE, schema.addScalarField(
		"L4_ICMP_TYPE_CODE",
		[](const void* context) { return static_cast<const ICMPData*>(context)->typeCode; }
	));

	return schema;
}

ICMPPlugin::ICMPPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createICMPSchema(manager, m_fieldHandlers);
}

PluginInitResult ICMPPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	// TODO :
	// values from dissector enums
	constexpr uint16_t ICMP_PROTO = 1;
	constexpr uint16_t ICMPV6_PROTO = 58;

	if (flowContext.packet.flowKey.l4Protocol != ICMP_PROTO && flowContext.packet.flowKey.l4Protocol != ICMPV6_PROTO) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}
	if (flowContext.packet.payload.size() < sizeof(ICMPData::typeCode)) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::NoAction,
		};
	}

	// the type and code are the first two bytes, type on MSB and code on LSB
	// in the network byte order
	std::construct_at(reinterpret_cast<ICMPData*>(pluginContext))->typeCode 
		= *reinterpret_cast<const uint16_t*>(flowContext.packet.payload.data());
	m_fieldHandlers[ICMPFields::L4_ICMP_TYPE_CODE].setAsAvailable(flowContext.flowRecord);

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::NoUpdateNeeded,
		.flowAction = FlowAction::NoAction,
	};
}

std::string ICMPPlugin::getName() const noexcept
{ 
	return icmpPluginManifest.name; 
}

static const PluginRegistrar<ICMPPlugin, 
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> icmpRegistrar(icmpPluginManifest);

} // namespace ipxp
