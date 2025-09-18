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

#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
//#include <pluginManifest.hpp>
//#include <pluginRegistrar.hpp>
//#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <tcpData.hpp>

namespace ipxp {

static const PluginManifest basicPlusPluginManifest = {
	.name = "basicplus",
	.description = "Basicplus process plugin for parsing basicplus traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			std::cout << "tes666" << std::endl;
			/*OptionsParser parser(
				"basicplus",
				"Extend basic fields with TTL, TCP window, options, MSS and SYN size");
			parser.usage(std::cout);*/
		},
};


static FieldSchema createBasicPlusSchema(FieldManager& fieldManager, FieldHandlers<BasicPlusFields>& handlers)
{
	FieldSchema schema = fieldManager.createFieldSchema("basicplus");

	auto [ipTTLField, ipTTLRevField] = schema.addScalarDirectionalFields(
    "IP_TTL", "IP_TTL_REV",
		[](const void* context) { return reinterpret_cast<const BasicPlusData*>(context)->ipTTL[Direction::Forward]; },
		[](const void* context) { return reinterpret_cast<const BasicPlusData*>(context)->ipTTL[Direction::Reverse]; }
	);
	handlers.insert(BasicPlusFields::IP_TTL, ipTTLField);
	handlers.insert(BasicPlusFields::IP_TTL_REV, ipTTLRevField);

	auto [ipFlagField, ipFlagRevField] = schema.addScalarDirectionalFields(
    "IP_FLG", "IP_FLG_REV",
		[](const void* context) { return reinterpret_cast<const BasicPlusData*>(context)->ipFlag[Direction::Forward]; },
		[](const void* context) { return reinterpret_cast<const BasicPlusData*>(context)->ipFlag[Direction::Reverse]; }
	);
	handlers.insert(BasicPlusFields::IP_FLG, ipFlagField);
	handlers.insert(BasicPlusFields::IP_FLG_REV, ipFlagRevField);

	auto [tcpWinField, tcpWinRevField] = schema.addScalarDirectionalFields(
    "TCP_WIN", "TCP_WIN_REV",
		[](const void* context) { return reinterpret_cast<const BasicPlusData*>(context)->tcpWindow[Direction::Forward]; },
		[](const void* context) { return reinterpret_cast<const BasicPlusData*>(context)->tcpWindow[Direction::Reverse]; }
	);
	handlers.insert(BasicPlusFields::TCP_WIN, tcpWinField);
	handlers.insert(BasicPlusFields::TCP_WIN_REV, tcpWinRevField);

	auto [tcpOptField, tcpOptRevField] = schema.addScalarDirectionalFields(
    "TCP_OPT", "TCP_OPT_REV",
		[](const void* context) { return reinterpret_cast<const BasicPlusData*>(context)->tcpOption[Direction::Forward]; },
		[](const void* context) { return reinterpret_cast<const BasicPlusData*>(context)->tcpOption[Direction::Reverse]; }
	);
	handlers.insert(BasicPlusFields::TCP_OPT, tcpOptField);
	handlers.insert(BasicPlusFields::TCP_OPT_REV, tcpOptRevField);

	auto [tcpMSSField, tcpMSSRevField] = schema.addScalarDirectionalFields(
    "TCP_MSS", "TCP_MSS_REV",
		[](const void* context) { return reinterpret_cast<const BasicPlusData*>(context)->tcpMSS[Direction::Forward]; },
		[](const void* context) { return reinterpret_cast<const BasicPlusData*>(context)->tcpMSS[Direction::Reverse]; }
	);
	handlers.insert(BasicPlusFields::TCP_MSS, tcpMSSField);
	handlers.insert(BasicPlusFields::TCP_MSS_REV, tcpMSSRevField);

	handlers.insert(BasicPlusFields::TCP_SYN_SIZE, schema.addScalarField("TCP_SYN_SIZE", [](const void* context) {
		return static_cast<const BasicPlusData*>(context)->tcpSynSize;
	}));

	return schema;
}

BasicPlusPlugin::BasicPlusPlugin([[maybe_unused]]const std::string& params, FieldManager& fieldManager)
{
	createBasicPlusSchema(fieldManager, m_fieldHandlers);
}

PluginInitResult BasicPlusPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<BasicPlusData*>(pluginContext));

	pluginData->ipTTL[Direction::Forward] = flowContext.packet.ip_ttl;
	m_fieldHandlers[BasicPlusFields::IP_TTL].setAsAvailable(flowContext.flowRecord);

	pluginData->ipFlag[Direction::Forward] = flowContext.packet.ip_flags;
	m_fieldHandlers[BasicPlusFields::IP_FLG].setAsAvailable(flowContext.flowRecord);

	constexpr std::size_t TCP = 6;
	if (flowContext.packet.ip_proto != TCP) {
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::NoAction,
		};
	}

	pluginData->tcpWindow[Direction::Forward] = flowContext.packet.tcp_window;
	m_fieldHandlers[BasicPlusFields::TCP_WIN].setAsAvailable(flowContext.flowRecord);

	pluginData->tcpOption[Direction::Forward] = flowContext.packet.tcp_options;
	m_fieldHandlers[BasicPlusFields::TCP_OPT].setAsAvailable(flowContext.flowRecord);

	pluginData->tcpMSS[Direction::Forward] = flowContext.packet.tcp_mss;
	m_fieldHandlers[BasicPlusFields::TCP_MSS].setAsAvailable(flowContext.flowRecord);

	if (TCPFlags(flowContext.packet.tcp_flags).bitfields.synchronize) { // check if SYN packet
		pluginData->tcpSynSize = flowContext.packet.ip_len;
		m_fieldHandlers[BasicPlusFields::TCP_SYN_SIZE].setAsAvailable(flowContext.flowRecord);
	}

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult BasicPlusPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<BasicPlusData*>(pluginContext);
	
	pluginData->ipTTL[flowContext.packet.source_pkt] 
		= std::min(pluginData->ipTTL[flowContext.packet.source_pkt], flowContext.packet.ip_ttl);

	constexpr std::size_t TCP = 6;
	if (flowContext.packet.ip_proto != TCP) {
		return {
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::NoAction,
		};
	}

	pluginData->tcpOption[flowContext.packet.source_pkt] |= flowContext.packet.tcp_options;

	if (flowContext.packet.source_pkt == Direction::Forward) {
		return {
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::NoAction,
		};
	}

	pluginData->ipTTL[Direction::Reverse] = flowContext.packet.ip_ttl;
	m_fieldHandlers[BasicPlusFields::IP_TTL_REV].setAsAvailable(flowContext.flowRecord);

	pluginData->ipFlag[Direction::Reverse] = flowContext.packet.ip_flags;
	m_fieldHandlers[BasicPlusFields::IP_FLG_REV].setAsAvailable(flowContext.flowRecord);

	pluginData->tcpWindow[Direction::Reverse] = flowContext.packet.tcp_window;
	m_fieldHandlers[BasicPlusFields::TCP_WIN_REV].setAsAvailable(flowContext.flowRecord);

	pluginData->tcpOption[Direction::Reverse] = flowContext.packet.tcp_options;
	m_fieldHandlers[BasicPlusFields::TCP_OPT_REV].setAsAvailable(flowContext.flowRecord);

	pluginData->tcpMSS[Direction::Reverse] = flowContext.packet.tcp_mss;
	m_fieldHandlers[BasicPlusFields::TCP_MSS_REV].setAsAvailable(flowContext.flowRecord);

	return {
		.updateRequirement = UpdateRequirement::NoUpdateNeeded,
		.flowAction = FlowAction::NoAction,
	};
}

void BasicPlusPlugin::onDestroy(void* pluginContext) 
{
	std::destroy_at(reinterpret_cast<BasicPlusData*>(pluginContext));
}

PluginDataMemoryLayout BasicPlusPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(BasicPlusData),
		.alignment = alignof(BasicPlusData),
	};
}

static const PluginRegistrar<BasicPlusPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	basicPlusRegistrar(basicPlusPluginManifest);

} // namespace ipxp
