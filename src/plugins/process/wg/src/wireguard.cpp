/**
 * @file
 * @brief Plugin for parsing wg traffic.
 * @author Pavel Valach <valacpav@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses Wireguard traffic,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "wireguard.hpp"

#include "wireguardGetters.hpp"
#include "wireguardPacketSize.hpp"
#include "wireguardPacketType.hpp"

#include <iostream>

#include <amon/layers/UDP.hpp>
#include <arpa/inet.h>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils.hpp>
#include <utils/spanUtils.hpp>

namespace ipxp::process::wireguard {

static const PluginManifest wireguardPluginManifest = {
	.name = "wg",
	.description = "Wg process plugin for parsing wg traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("wg", "Parse WireGuard traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createWireguardSchema(FieldManager& fieldManager, FieldHandlers<WireguardFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("wg");

	handlers.insert(
		WireguardFields::WG_CONF_LEVEL,
		schema.addScalarField("WG_CONF_LEVEL", getWireguardConfidenceLevelField));

	auto [srcPeerHandler, dstPeerHandler] = schema.addScalarBiflowFields(
		"WG_SRC_PEER",
		"WG_DST_PEER",
		getWireguardSrcPeerField,
		getWireguardDstPeerField);
	handlers.insert(WireguardFields::WG_SRC_PEER, srcPeerHandler);
	handlers.insert(WireguardFields::WG_DST_PEER, dstPeerHandler);

	return schema;
}

WireguardPlugin::WireguardPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createWireguardSchema(manager, m_fieldHandlers);
}

OnInitResult WireguardPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	if (!flowContext.packetContext.packet
			 ->getLayerView<amon::layers::UDPView>(std::get<amon::PacketLayer>(
				 flowContext.packetContext.packet
					 ->layers[*flowContext.packetContext.packet->layout.l4]))
			 .has_value()) {
		return OnInitResult::Irrelevant;
	}

	auto& wireguardContext = *std::construct_at(reinterpret_cast<WireguardContext*>(pluginContext));
	const bool parsed = parseWireguard(
		getPayload(*flowContext.packetContext.packet),
		flowContext.packetDirection,
		wireguardContext,
		flowContext.flowRecord);
	return parsed ? OnInitResult::ConstructedNeedsUpdate : OnInitResult::ConstructedFinal;
}

OnUpdateResult WireguardPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& wireguardContext = *reinterpret_cast<WireguardContext*>(pluginContext);
	const bool parsed = parseWireguard(
		getPayload(*flowContext.packetContext.packet),
		flowContext.packetDirection,
		wireguardContext,
		flowContext.flowRecord);
	return parsed ? OnUpdateResult::NeedsUpdate : OnUpdateResult::Final;
}

constexpr static bool isValidPacketType(const WireguardPacketType type) noexcept
{
	return type >= WireguardPacketType::HANDSHAKE_INIT
		&& type <= WireguardPacketType::TRANSPORT_DATA;
}

constexpr static std::size_t getPacketSize(const WireguardPacketType type) noexcept
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

constexpr static bool checkReservedBytes(std::span<const std::byte> payload) noexcept
{
	return payload[1] == std::byte {0x0} && payload[2] == std::byte {0x0}
	&& payload[3] == std::byte {0x0};
}

constexpr static bool
checkPacketSize(const WireguardPacketType type, const std::size_t size) noexcept
{
	switch (type) {
	case WireguardPacketType::HANDSHAKE_INIT:
		[[fallthrough]];
	case WireguardPacketType::HANDSHAKE_RESPONSE:
		[[fallthrough]];
	case WireguardPacketType::COOCKIE_REPLY:
		return size == getPacketSize(type);
	case WireguardPacketType::TRANSPORT_DATA:
		return size >= static_cast<std::size_t>(WireguardPacketSize::MIN_TRANSPORT_DATA_SIZE);
	}

	__builtin_unreachable();
}

BeforeUpdateResult
WireguardPlugin::beforeUpdate(const FlowContext& flowContext, const void* pluginContext) const
{
	const auto payload = getPayload(*flowContext.packetContext.packet);
	const auto type = static_cast<WireguardPacketType>(payload[0]);
	const auto& wireguardContext = *reinterpret_cast<const WireguardContext*>(pluginContext);
	if (!isValidPacketType(type) || checkPacketSize(type, payload.size())
		|| !checkReservedBytes(payload)) {
		return BeforeUpdateResult::NoAction;
	}

	constexpr std::size_t senderIndexOffset = 4;
	const uint32_t senderIndex
		= ntohl(*reinterpret_cast<const uint32_t*>(payload.data() + senderIndexOffset));

	if (type == WireguardPacketType::HANDSHAKE_INIT) {
		// compare the current dst_peer and see if it matches the original source.
		// If not, the flow flush may be needed to create a new flow.

		const std::optional<uint32_t> savedPeer
			= wireguardContext.peer[flowContext.packetDirection];
		if (savedPeer.has_value() && senderIndex != *savedPeer) {
			return BeforeUpdateResult::FlushFlowAndReinsert;
		}
	}

	return BeforeUpdateResult::NoAction;
}

bool WireguardPlugin::parseWireguard(
	std::span<const std::byte> payload,
	const Direction direction,
	WireguardContext& wireguardContext,
	FlowRecord& flowRecord) noexcept
{
	const auto type = static_cast<WireguardPacketType>(payload[0]);
	if (!isValidPacketType(type) || checkPacketSize(type, payload.size())
		|| !checkReservedBytes(payload)) {
		wireguardContext.confidence = 0;
		m_fieldHandlers[WireguardFields::WG_CONF_LEVEL].setAsAvailable(flowRecord);
		return false;
	}

	constexpr std::size_t senderIndexOffset = 4;
	const uint32_t senderIndex
		= ntohl(*reinterpret_cast<const uint32_t*>(payload.data() + senderIndexOffset));

	switch (type) {
	case WireguardPacketType::HANDSHAKE_INIT: {
		wireguardContext.peer[direction] = senderIndex;

		break;
	}
	case WireguardPacketType::HANDSHAKE_RESPONSE: {
		wireguardContext.peer[direction] = senderIndex;

		constexpr std::size_t dstPeerOffset = 8;
		wireguardContext.peer[static_cast<Direction>(!direction)]
			= ntohl(*reinterpret_cast<const uint32_t*>(payload.data() + dstPeerOffset));

		m_fieldHandlers[WireguardFields::WG_SRC_PEER].setAsAvailable(flowRecord);
		m_fieldHandlers[WireguardFields::WG_DST_PEER].setAsAvailable(flowRecord);

		break;
	}
	case WireguardPacketType::COOCKIE_REPLY:
		[[fallthrough]];
	case WireguardPacketType::TRANSPORT_DATA:
		constexpr auto mapping
			= std::to_array({WireguardFields::WG_SRC_PEER, WireguardFields::WG_DST_PEER});

		wireguardContext.peer[direction] = senderIndex;
		m_fieldHandlers[mapping[direction]].setAsAvailable(flowRecord);

		break;
	}

	// Possible misdetection
	// - DNS request
	//   Can happen when transaction ID is >= 1 and <= 4, the query is non-recursive
	//   and other flags are zeros, too.
	//   2B transaction ID, 2B flags, 2B questions count, 2B answers count
	constexpr std::array<std::byte, 4> dnsQueryMask {
		std::byte {0x00},
		std::byte {0x01},
		std::byte {0x00},
		std::byte {0x00}};
	const bool matchesMask = std::ranges::equal(dnsQueryMask, payload.subspan(senderIndexOffset));
	if (matchesMask) {
		wireguardContext.confidence = 1;
		m_fieldHandlers[WireguardFields::WG_CONF_LEVEL].setAsAvailable(flowRecord);

		return false;
	}
	wireguardContext.confidence = 100;
	m_fieldHandlers[WireguardFields::WG_CONF_LEVEL].setAsAvailable(flowRecord);

	return true;
}

void WireguardPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<WireguardContext*>(pluginContext));
}

PluginDataMemoryLayout WireguardPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(WireguardContext),
		.alignment = alignof(WireguardContext),
	};
}

static const PluginRegistrar<
	WireguardPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	wireguardRegistrar(wireguardPluginManifest);

} // namespace ipxp::process::wireguard
