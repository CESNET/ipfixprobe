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

#include "tcpOptions.hpp"

#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <tcpData.hpp>

namespace ipxp {

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
		[](const void* context) {
			return reinterpret_cast<const BasicPlusData*>(context)->ipTTL[Direction::Forward];
		},
		[](const void* context) {
			return reinterpret_cast<const BasicPlusData*>(context)->ipTTL[Direction::Reverse];
		});
	handlers.insert(BasicPlusFields::IP_TTL, ipTTLField);
	handlers.insert(BasicPlusFields::IP_TTL_REV, ipTTLRevField);

	auto [ipFlagField, ipFlagRevField] = schema.addScalarDirectionalFields(
		"IP_FLG",
		"IP_FLG_REV",
		[](const void* context) {
			return reinterpret_cast<const BasicPlusData*>(context)->ipFlag[Direction::Forward];
		},
		[](const void* context) {
			return reinterpret_cast<const BasicPlusData*>(context)->ipFlag[Direction::Reverse];
		});
	handlers.insert(BasicPlusFields::IP_FLG, ipFlagField);
	handlers.insert(BasicPlusFields::IP_FLG_REV, ipFlagRevField);

	auto [tcpWinField, tcpWinRevField] = schema.addScalarDirectionalFields(
		"TCP_WIN",
		"TCP_WIN_REV",
		[](const void* context) {
			return reinterpret_cast<const BasicPlusData*>(context)->tcpWindow[Direction::Forward];
		},
		[](const void* context) {
			return reinterpret_cast<const BasicPlusData*>(context)->tcpWindow[Direction::Reverse];
		});
	handlers.insert(BasicPlusFields::TCP_WIN, tcpWinField);
	handlers.insert(BasicPlusFields::TCP_WIN_REV, tcpWinRevField);

	auto [tcpOptField, tcpOptRevField] = schema.addScalarDirectionalFields(
		"TCP_OPT",
		"TCP_OPT_REV",
		[](const void* context) {
			return reinterpret_cast<const BasicPlusData*>(context)->tcpOption[Direction::Forward];
		},
		[](const void* context) {
			return reinterpret_cast<const BasicPlusData*>(context)->tcpOption[Direction::Reverse];
		});
	handlers.insert(BasicPlusFields::TCP_OPT, tcpOptField);
	handlers.insert(BasicPlusFields::TCP_OPT_REV, tcpOptRevField);

	auto [tcpMSSField, tcpMSSRevField] = schema.addScalarDirectionalFields(
		"TCP_MSS",
		"TCP_MSS_REV",
		[](const void* context) {
			return reinterpret_cast<const BasicPlusData*>(context)->tcpMSS[Direction::Forward];
		},
		[](const void* context) {
			return reinterpret_cast<const BasicPlusData*>(context)->tcpMSS[Direction::Reverse];
		});
	handlers.insert(BasicPlusFields::TCP_MSS, tcpMSSField);
	handlers.insert(BasicPlusFields::TCP_MSS_REV, tcpMSSRevField);

	handlers.insert(
		BasicPlusFields::TCP_SYN_SIZE,
		schema.addScalarField("TCP_SYN_SIZE", [](const void* context) {
			return static_cast<const BasicPlusData*>(context)->tcpSynSize;
		}));

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
	if (auto ipv4 = packet.getLayerView<amon::IPv4View>()) {
		return ipv4->ttl();
	} else if (auto ipv6 = packet.getLayerView<amon::IPv6View>()) {
		return ipv6->hopLimit();
	}

	std::unreachable();
}

PluginInitResult BasicPlusPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<BasicPlusData*>(pluginContext));

	pluginData->ipTTL[Direction::Forward] = getTTL(flowContext.packet);
	m_fieldHandlers[BasicPlusFields::IP_TTL].setAsAvailable(flowContext.flowRecord);

	if (auto ipv4 = flowContext.packet.getLayerView<amon::layers::IPv4View>(); ipv4.has_value()) {
		pluginData->ipFlag[Direction::Forward] = ipv4->ipFlags();
		m_fieldHandlers[BasicPlusFields::IP_FLG].setAsAvailable(flowContext.flowRecord);
	}

	constexpr std::size_t TCP = 6;
	if (flowContext.flowRecord.flowKey.l4Protocol != TCP) {
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::NoAction,
		};
	}

	if (!flowContext.features.tcp.has_value()) {
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::NoAction,
		};
	}

	pluginData->tcpWindow[Direction::Forward] = flowContext.features.tcp->window();
	m_fieldHandlers[BasicPlusFields::TCP_WIN].setAsAvailable(flowContext.flowRecord);

	if (flowContext.features.tcpOptions.has_value()) {
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::NoAction,
		};
	}

	pluginData->tcpOption[Direction::Forward] = flowContext.features.tcpOptions->ipfixCumulative;
	m_fieldHandlers[BasicPlusFields::TCP_OPT].setAsAvailable(flowContext.flowRecord);

	if (!flowContext.features.tcpOptions->mss.has_value()) {
		pluginData->tcpMSS[Direction::Forward] = *flowContext.features.tcpOptions->mss;
		m_fieldHandlers[BasicPlusFields::TCP_MSS].setAsAvailable(flowContext.flowRecord);
	}

	if (TCPFlags(flowContext.features.tcp->flags()).bitfields.synchronize) { // check if SYN packet
		pluginData->tcpSynSize = flowContext.flowRecord.directionalData[Direction::Forward].bytes;
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

	const uint8_t ttl = getTTL(flowContext.packet);
	pluginData->ipTTL[flowContext.features.direction]
		= std::min(pluginData->ipTTL[flowContext.features.direction], ttl);

	if (!flowContext.features.tcp.has_value()) {
		return {
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::NoAction,
		};
	}

	if (flowContext.features.tcpOptions.has_value()) {
		pluginData->tcpOption[flowContext.features.direction]
			|= flowContext.features.tcpOptions->ipfixCumulative;
	}

	if (flowContext.features.direction == Direction::Forward) {
		return {
			.updateRequirement = UpdateRequirement::RequiresUpdate,
			.flowAction = FlowAction::NoAction,
		};
	}

	pluginData->ipTTL[Direction::Reverse] = ttl;
	m_fieldHandlers[BasicPlusFields::IP_TTL_REV].setAsAvailable(flowContext.flowRecord);

	if (auto ipv4 = flowContext.packet.getLayerView<amon::layers::IPv4View>(); ipv4.has_value()) {
		pluginData->ipFlag[Direction::Reverse] = ipv4->ipFlags();
		m_fieldHandlers[BasicPlusFields::IP_FLG_REV].setAsAvailable(flowContext.flowRecord);
	}

	pluginData->tcpWindow[Direction::Reverse] = flowContext.features.tcp->window();
	m_fieldHandlers[BasicPlusFields::TCP_WIN_REV].setAsAvailable(flowContext.flowRecord);

	if (flowContext.features.tcpOptions.has_value()) {
		pluginData->tcpOption[Direction::Reverse]
			= flowContext.features.tcpOptions->ipfixCumulative;
		m_fieldHandlers[BasicPlusFields::TCP_OPT_REV].setAsAvailable(flowContext.flowRecord);

		if (flowContext.features.tcpOptions->mss.has_value()) {
			pluginData->tcpMSS[Direction::Reverse] = *flowContext.features.tcpOptions->mss;
			m_fieldHandlers[BasicPlusFields::TCP_MSS_REV].setAsAvailable(flowContext.flowRecord);
		}
	}

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

static const PluginRegistrar<BasicPlusPlugin, ProcessPluginFactory>
	basicPlusRegistrar(basicPlusPluginManifest);

} // namespace ipxp
