/**
 * @file
 * @brief Plugin for parsing icmp traffic.
 * @author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts ICMP typecode from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "icmp.hpp"

#include "icmpContext.hpp"
#include "icmpGetters.hpp"

#include <iostream>

#include <amon/layers/ICMP.hpp>
#include <amon/layers/ICMPv6.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>

namespace ipxp::process::icmp {

static const PluginManifest icmpPluginManifest = {
	.name = "icmp",
	.description = "ICMP process plugin for parsing icmp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("icmp", "Parse ICMP traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup createICMPSchema(FieldManager& fieldManager, FieldHandlers<ICMPFields>& handlers)
{
	FieldGroup schema = fieldManager.createFieldGroup("icmp");

	handlers.insert(
		ICMPFields::L4_ICMP_TYPE_CODE,
		schema.addScalarField("L4_ICMP_TYPE_CODE", getICMPTypeCodeField));

	handlers.insert(
		ICMPFields::L4_ICMP_CODE,
		schema.addScalarField("L4_ICMP_CODE", getICMPCodeField));

	handlers.insert(
		ICMPFields::L4_ICMP_TYPE,
		schema.addScalarField("L4_ICMP_TYPE", getICMPTypeField));

	return schema;
}

ICMPPlugin::ICMPPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createICMPSchema(manager, m_fieldHandlers);
}

static bool isICMP(const amon::Packet& packet) noexcept
{
	return getLayerView<amon::layers::ICMPView>(packet, packet.layout.l4).has_value()
		|| getLayerView<amon::layers::ICMPv6View>(packet, packet.layout.l4).has_value();
}

OnInitResult ICMPPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	if (!isICMP(*flowContext.packetContext.packet)) {
		return OnInitResult::Irrelevant;
	}

	if (getIPPayloadLength(*flowContext.packetContext.packet) < sizeof(ICMPContext::typeCode)) {
		return OnInitResult::PendingConstruction;
	}

	// the type and code are the first two bytes, type on MSB and code on LSB
	// in the network byte order
	auto& icmpContext = *std::construct_at(reinterpret_cast<ICMPContext*>(pluginContext));
	icmpContext.typeCode
		= *reinterpret_cast<const uint16_t*>(getPayload(*flowContext.packetContext.packet).data());
	m_fieldHandlers[ICMPFields::L4_ICMP_TYPE_CODE].setAsAvailable(flowContext.flowRecord);
	m_fieldHandlers[ICMPFields::L4_ICMP_CODE].setAsAvailable(flowContext.flowRecord);
	m_fieldHandlers[ICMPFields::L4_ICMP_TYPE].setAsAvailable(flowContext.flowRecord);

	return OnInitResult::ConstructedFinal;
}

void ICMPPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<ICMPContext*>(pluginContext));
}

PluginDataMemoryLayout ICMPPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(ICMPContext),
		.alignment = alignof(ICMPContext),
	};
}

static const PluginRegistrar<
	ICMPPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	icmpRegistrar(icmpPluginManifest);

} // namespace ipxp::process::icmp
