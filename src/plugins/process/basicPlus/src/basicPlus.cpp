/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts basic IP and TCP fields from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "basicPlus.hpp"

#include "basicPlusContext.hpp"
#include "basicPlusGetters.hpp"
#include "tcpOptions.hpp"

#include <iostream>

#include <amon/layers/IPv4.hpp>
#include <amon/layers/IPv6.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <tcpData.hpp>

namespace ipxp::process::basicPlus {

static const PluginManifest basicPlusPluginManifest = {
	.name = "basicplus",
	.description = "Basicplus process plugin for parsing basicplus traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser(
				"basicplus",
				"Extend basic fields with TTL, TCP window, options, MSS and SYN size");
			parser.usage(std::cout);
		},
};

#undef IP_TTL

static FieldGroup
createBasicPlusSchema(FieldManager& fieldManager, FieldHandlers<BasicPlusFields>& handlers)
{
	FieldGroup schema = fieldManager.createFieldGroup("basicplus");

	auto [ipTTLField, ipTTLRevField] = schema.addScalarDirectionalFields(
		"IP_TTL",
		"IP_TTL_REV",
		[](const void* context) { return getIPTTLField(context, Direction::Forward); },
		[](const void* context) { return getIPTTLField(context, Direction::Reverse); });
	handlers.insert(BasicPlusFields::IP_TTL, ipTTLField);
	handlers.insert(BasicPlusFields::IP_TTL_REV, ipTTLRevField);

	auto [ipFlagField, ipFlagRevField] = schema.addScalarDirectionalFields(
		"IP_FLG",
		"IP_FLG_REV",
		[](const void* context) { return getIPFlagField(context, Direction::Forward); },
		[](const void* context) { return getIPFlagField(context, Direction::Reverse); });
	handlers.insert(BasicPlusFields::IP_FLG, ipFlagField);
	handlers.insert(BasicPlusFields::IP_FLG_REV, ipFlagRevField);

	auto [tcpWinField, tcpWinRevField] = schema.addScalarDirectionalFields(
		"TCP_WIN",
		"TCP_WIN_REV",
		[](const void* context) { return getTCPWindowField(context, Direction::Forward); },
		[](const void* context) { return getTCPWindowField(context, Direction::Reverse); });
	handlers.insert(BasicPlusFields::TCP_WIN, tcpWinField);
	handlers.insert(BasicPlusFields::TCP_WIN_REV, tcpWinRevField);

	auto [tcpOptField, tcpOptRevField] = schema.addScalarDirectionalFields(
		"TCP_OPT",
		"TCP_OPT_REV",
		[](const void* context) { return getTCPOptionField(context, Direction::Forward); },
		[](const void* context) { return getTCPOptionField(context, Direction::Reverse); });
	handlers.insert(BasicPlusFields::TCP_OPT, tcpOptField);
	handlers.insert(BasicPlusFields::TCP_OPT_REV, tcpOptRevField);

	auto [tcpMSSField, tcpMSSRevField] = schema.addScalarDirectionalFields(
		"TCP_MSS",
		"TCP_MSS_REV",
		[](const void* context) { return getTCPMSSField(context, Direction::Forward); },
		[](const void* context) { return getTCPMSSField(context, Direction::Reverse); });
	handlers.insert(BasicPlusFields::TCP_MSS, tcpMSSField);
	handlers.insert(BasicPlusFields::TCP_MSS_REV, tcpMSSRevField);

	handlers.insert(
		BasicPlusFields::TCP_SYN_SIZE,
		schema.addScalarField("TCP_SYN_SIZE", getTCPSynSizeField));

	return schema;
}

BasicPlusPlugin::BasicPlusPlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& fieldManager)
{
	createBasicPlusSchema(fieldManager, m_fieldHandlers);
}

uint8_t getTTL(const amon::Packet& packet) noexcept
{
	if (auto ipv4 = packet.getLayerView<amon::layers::IPv4View>(
			std::get<amon::PacketLayer>(packet.layers[*packet.layout.l3]))) {
		return ipv4->ttl();
	} else if (
		auto ipv6 = packet.getLayerView<amon::layers::IPv6View>(
			std::get<amon::PacketLayer>(packet.layers[*packet.layout.l4]))) {
		return ipv6->hopLimit();
	}

	std::unreachable();
}

OnInitResult BasicPlusPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto& basicPlusContext = *std::construct_at(reinterpret_cast<BasicPlusContext*>(pluginContext));

	basicPlusContext.ipTTL[Direction::Forward] = getTTL(*flowContext.packetContext.packet);
	m_fieldHandlers[BasicPlusFields::IP_TTL].setAsAvailable(flowContext.flowRecord);

	if (auto ipv4 = flowContext.packetContext.packet->getLayerView<amon::layers::IPv4View>(
			std::get<amon::PacketLayer>(
				flowContext.packetContext.packet
					->layers[*flowContext.packetContext.packet->layout.l3]));
		ipv4.has_value()) {
		basicPlusContext.ipFlag[Direction::Forward] = ipv4->ipFlags();
		m_fieldHandlers[BasicPlusFields::IP_FLG].setAsAvailable(flowContext.flowRecord);
	}

	if (!flowContext.packetContext.features->tcp.has_value()) {
		return OnInitResult::ConstructedNeedsUpdate;
	}

	basicPlusContext.tcpWindow[Direction::Forward]
		= flowContext.packetContext.features->tcp->window();
	m_fieldHandlers[BasicPlusFields::TCP_WIN].setAsAvailable(flowContext.flowRecord);

	if (flowContext.packetContext.features->tcpOptions.has_value()) {
		return OnInitResult::ConstructedNeedsUpdate;
	}

	basicPlusContext.tcpOption[Direction::Forward]
		= flowContext.packetContext.features->tcpOptions->ipfixCumulative;
	m_fieldHandlers[BasicPlusFields::TCP_OPT].setAsAvailable(flowContext.flowRecord);

	if (!flowContext.packetContext.features->tcpOptions->mss.has_value()) {
		basicPlusContext.tcpMSS[Direction::Forward]
			= *flowContext.packetContext.features->tcpOptions->mss;
		m_fieldHandlers[BasicPlusFields::TCP_MSS].setAsAvailable(flowContext.flowRecord);
	}

	if (TCPFlags(flowContext.packetContext.features->tcp->flags())
			.bitfields.synchronize) { // check if SYN packet
		basicPlusContext.tcpSynSize
			= flowContext.flowRecord.directionalData[Direction::Forward].bytes;
		m_fieldHandlers[BasicPlusFields::TCP_SYN_SIZE].setAsAvailable(flowContext.flowRecord);
	}

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult BasicPlusPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	BasicPlusContext& basicPlusContext = *reinterpret_cast<BasicPlusContext*>(pluginContext);

	const uint8_t ttl = getTTL(*flowContext.packetContext.packet);
	basicPlusContext.ipTTL[flowContext.packetDirection]
		= std::min(basicPlusContext.ipTTL[flowContext.packetDirection], ttl);

	if (!flowContext.packetContext.features->tcp.has_value()) {
		return OnUpdateResult::NeedsUpdate;
	}

	if (flowContext.packetContext.features->tcpOptions.has_value()) {
		basicPlusContext.tcpOption[flowContext.packetContext.features->direction]
			|= flowContext.packetContext.features->tcpOptions->ipfixCumulative;
	}

	if (flowContext.packetContext.features->direction == Direction::Forward) {
		return OnUpdateResult::NeedsUpdate;
	}

	basicPlusContext.ipTTL[Direction::Reverse] = ttl;
	m_fieldHandlers[BasicPlusFields::IP_TTL_REV].setAsAvailable(flowContext.flowRecord);

	if (auto ipv4 = flowContext.packetContext.packet->getLayerView<amon::layers::IPv4View>(
			std::get<amon::PacketLayer>(
				flowContext.packetContext.packet
					->layers[*flowContext.packetContext.packet->layout.l3]));
		ipv4.has_value()) {
		basicPlusContext.ipFlag[Direction::Reverse] = ipv4->ipFlags();
		m_fieldHandlers[BasicPlusFields::IP_FLG_REV].setAsAvailable(flowContext.flowRecord);
	}

	basicPlusContext.tcpWindow[Direction::Reverse]
		= flowContext.packetContext.features->tcp->window();
	m_fieldHandlers[BasicPlusFields::TCP_WIN_REV].setAsAvailable(flowContext.flowRecord);

	if (flowContext.packetContext.features->tcpOptions.has_value()) {
		basicPlusContext.tcpOption[Direction::Reverse]
			= flowContext.packetContext.features->tcpOptions->ipfixCumulative;
		m_fieldHandlers[BasicPlusFields::TCP_OPT_REV].setAsAvailable(flowContext.flowRecord);

		if (flowContext.packetContext.features->tcpOptions->mss.has_value()) {
			basicPlusContext.tcpMSS[Direction::Reverse]
				= *flowContext.packetContext.features->tcpOptions->mss;
			m_fieldHandlers[BasicPlusFields::TCP_MSS_REV].setAsAvailable(flowContext.flowRecord);
		}
	}

	return OnUpdateResult::Final;
}

void BasicPlusPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<BasicPlusContext*>(pluginContext));
}

PluginDataMemoryLayout BasicPlusPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(BasicPlusContext),
		.alignment = alignof(BasicPlusContext),
	};
}

static const PluginRegistrar<BasicPlusPlugin, ProcessPluginFactory>
	basicPlusRegistrar(basicPlusPluginManifest);

} // namespace ipxp::process::basicPlus
