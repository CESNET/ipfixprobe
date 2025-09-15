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

#include "wireguard.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>
#include <arpa/inet.h>
#include <utils/spanUtils.hpp>

#include "wireguardPacketType.hpp"
#include "wireguardPacketSize.hpp"

namespace ipxp {

static const PluginManifest wireguardPluginManifest = {
	.name = "wg",
	.description = "Wg process plugin for parsing wg traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("wg", "Parse WireGuard traffic");
			parser.usage(std::cout);*/
		},
};

static FieldSchema createWireguardSchema(FieldManager& fieldManager, FieldHandlers<WireguardFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("wg");

	handlers.insert(WireguardFields::WG_CONF_LEVEL, schema.addScalarField(
		"WG_CONF_LEVEL",
		[](const void* context) { return reinterpret_cast<const WireguardData*>(context)->confidence; }
	));

	auto [srcPeerHandler, dstPeerHandler] = schema.addScalarBiflowFields(
		"WG_SRC_PEER",
		"WG_DST_PEER",
		[](const void* context) { return *reinterpret_cast<const WireguardData*>(context)->peer[Direction::Forward]; },
		[](const void* context) { return *reinterpret_cast<const WireguardData*>(context)->peer[Direction::Reverse]; }
	);
	handlers.insert(WireguardFields::WG_SRC_PEER, srcPeerHandler);
	handlers.insert(WireguardFields::WG_DST_PEER, dstPeerHandler);
	
	return schema;
}

WireguardPlugin::WireguardPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createWireguardSchema(manager, m_fieldHandlers);
}

PluginInitResult WireguardPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	// TODO DISSECTOR VALUE
	constexpr uint8_t UDP = 17;
	if (flowContext.packet.ip_proto != UDP) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<WireguardData*>(pluginContext));
	auto [updateRequirement, flowAction] = parseWireguard(toSpan<const std::byte>(
		flowContext.packet.payload, flowContext.packet.payload_len), flowContext.packet.source_pkt, *pluginData, flowContext.flowRecord);
	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = updateRequirement,
		.flowAction = flowAction,
	};
}

PluginUpdateResult WireguardPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<WireguardData*>(pluginContext);
	return parseWireguard(toSpan<const std::byte>(
		flowContext.packet.payload, flowContext.packet.payload_len), flowContext.packet.source_pkt, *pluginData, flowContext.flowRecord);
}

constexpr static
bool isValidPacketType(const WireguardPacketType type) noexcept
{
	return type >= WireguardPacketType::HANDSHAKE_INIT &&
		type <= WireguardPacketType::TRANSPORT_DATA;
}

constexpr static
std::size_t getPacketSize(const WireguardPacketType type) noexcept
{
	switch (type) {
	case WireguardPacketType::HANDSHAKE_INIT:
		return static_cast<std::size_t>(WireguardPacketSize::HANDSHAKE_INIT_SIZE);
	case WireguardPacketType::HANDSHAKE_RESPONSE:
		return static_cast<std::size_t>(WireguardPacketSize::HANDSHAKE_RESPONSE_SIZE);
	case WireguardPacketType::COOCKIE_REPLY:
		return static_cast<std::size_t>(WireguardPacketSize::COOCKIE_REPLY_SIZE);
	case WireguardPacketType::TRANSPORT_DATA:
		return static_cast<std::size_t>(WireguardPacketSize::MIN_TRANSPORT_DATA_SIZE);
	}

	__builtin_unreachable();
}

constexpr static
bool checkReservedBytes(std::span<const std::byte> payload) noexcept
{
	return payload[1] == std::byte{0x0} && payload[2] == std::byte{0x0} && payload[3] == std::byte{0x0};
}

constexpr static
bool checkPacketSize(
	const WireguardPacketType type, const std::size_t size) noexcept
{
	switch (type) {
	case WireguardPacketType::HANDSHAKE_INIT: [[fallthrough]];
	case WireguardPacketType::HANDSHAKE_RESPONSE: [[fallthrough]];
	case WireguardPacketType::COOCKIE_REPLY:
		return size == getPacketSize(type);
	case WireguardPacketType::TRANSPORT_DATA:
		return size >= static_cast<std::size_t>(WireguardPacketSize::MIN_TRANSPORT_DATA_SIZE);
	}

	__builtin_unreachable();
}

constexpr
PluginUpdateResult WireguardPlugin::parseWireguard(
	std::span<const std::byte> payload, const Direction direction, WireguardData& pluginData, FlowRecord& flowRecord) noexcept
{
	const auto type = static_cast<WireguardPacketType>(payload[0]);
	if (!isValidPacketType(type) || checkPacketSize(type, payload.size())) {
		pluginData.confidence = 0;
		m_fieldHandlers[WireguardFields::WG_CONF_LEVEL].setAsAvailable(flowRecord);
		
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		}; 
	}

	if (!checkReservedBytes(payload)) {
		pluginData.confidence = 0;
		m_fieldHandlers[WireguardFields::WG_CONF_LEVEL].setAsAvailable(flowRecord);

		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}

	constexpr std::size_t senderIndexOffset = 4;
	const uint32_t senderIndex = ntohl(
				*reinterpret_cast<const uint32_t*>(payload.data() + senderIndexOffset));

	switch (type) {
	case WireguardPacketType::HANDSHAKE_INIT: {
		// compare the current dst_peer and see if it matches the original source.
		// If not, the flow flush may be needed to create a new flow.

		const std::optional<uint32_t> savedPeer = pluginData.peer[direction];

		if (savedPeer.has_value() && 
			senderIndex != *savedPeer) {
			// TODO FLUSH AND REINSERT
			return {
				.updateRequirement = UpdateRequirement::NoUpdateNeeded,
				.flowAction = FlowAction::Flush,
			};
		}
		pluginData.peer[direction] = senderIndex;

		break;
	}
	case WireguardPacketType::HANDSHAKE_RESPONSE: {
		pluginData.peer[direction] = senderIndex;

		constexpr std::size_t dstPeerOffset = 8;
		pluginData.peer[static_cast<Direction>(!direction)] 
			= ntohl(*reinterpret_cast<const uint32_t*>(payload.data() + dstPeerOffset));

		m_fieldHandlers[WireguardFields::WG_SRC_PEER].setAsAvailable(flowRecord);
		m_fieldHandlers[WireguardFields::WG_DST_PEER].setAsAvailable(flowRecord);

		break;
	}
	case WireguardPacketType::COOCKIE_REPLY: [[fallthrough]];
	case WireguardPacketType::TRANSPORT_DATA:
		constexpr auto mapping = std::to_array({
			WireguardFields::WG_SRC_PEER,
			WireguardFields::WG_DST_PEER
		});

		pluginData.peer[direction] = senderIndex;
		m_fieldHandlers[mapping[direction]].setAsAvailable(flowRecord);
		
		break;
	}

	// Possible misdetection
	// - DNS request
	//   Can happen when transaction ID is >= 1 and <= 4, the query is non-recursive
	//   and other flags are zeros, too.
	//   2B transaction ID, 2B flags, 2B questions count, 2B answers count
	constexpr std::array<std::byte, 4> dnsQueryMask{std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}};
	const bool matchesMask 
		= std::ranges::equal(dnsQueryMask, payload.subspan(senderIndexOffset));
	if (matchesMask) {
		pluginData.confidence = 1;
		m_fieldHandlers[WireguardFields::WG_CONF_LEVEL].setAsAvailable(flowRecord);

		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}
	pluginData.confidence = 100;
	m_fieldHandlers[WireguardFields::WG_CONF_LEVEL].setAsAvailable(flowRecord);

	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

void WireguardPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<WireguardData*>(pluginContext));
}

PluginDataMemoryLayout WireguardPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(WireguardData),
		.alignment = alignof(WireguardData),
	};
}

static const PluginRegistrar<WireguardPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	wireguardRegistrar(wireguardPluginManifest);

} // namespace ipxp
