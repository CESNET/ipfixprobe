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

const inline std::vector<FieldPair<WireguardFields>> fields = {
	{WireguardFields::WG_CONF_LEVEL, "WG_CONF_LEVEL"},
	{WireguardFields::WG_SRC_PEER, "WG_SRC_PEER"},
	{WireguardFields::WG_DST_PEER, "WG_DST_PEER"},
};


static FieldSchema createWireguardSchema()
{
	FieldSchema schema("wg");

	/*schema.addScalarField<uint8_t>(
		"WG_CONF_LEVEL",
		FieldDirection::DirectionalIndifferent,
		offsetof(WireguardExport, confidence));

	schema.addScalarField<uint32_t>(
		"WG_SRC_PEER",
		FieldDirection::DirectionalIndifferent,
		offsetof(WireguardExport, peer[Direction::Forward]));

	schema.addScalarField<uint32_t>(
		"WG_DST_PEER",
		FieldDirection::DirectionalIndifferent,
		offsetof(WireguardExport, peer[Direction::Reverse]));*/

	return schema;
}

WireguardPlugin::WireguardPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createWireguardSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction WireguardPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	constexpr uint8_t UDP = 17;
	if (packet.flowKey.l4Protocol != UDP) {
	return FlowAction::RequestNoData;
	}

	return parseWireguard(packet.payload, packet.direction);
}

FlowAction WireguardPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	return parseWireguard(packet.payload, packet.direction);
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
FlowAction WireguardPlugin::parseWireguard(
	std::span<const std::byte> payload, const Direction direction) noexcept
{
	const auto type = static_cast<WireguardPacketType>(payload[0]);
	if (!isValidPacketType(type) || checkPacketSize(type, payload.size())) {
		m_exportData.confidence = 0;
		return FlowAction::RequestNoData;
	}

	if (!checkReservedBytes(payload)) {
		m_exportData.confidence = 0;
		return FlowAction::RequestNoData;
	}

	constexpr std::size_t senderIndexOffset = 4;
	const uint32_t senderIndex = ntohl(
				*reinterpret_cast<const uint32_t*>(payload.data() + senderIndexOffset));

	switch (type) {
	case WireguardPacketType::HANDSHAKE_INIT: {
		// compare the current dst_peer and see if it matches the original source.
		// If not, the flow flush may be needed to create a new flow.

		const std::optional<uint32_t> savedPeer 
			= m_exportData.peer[direction]; 

		if (savedPeer.has_value() && 
			senderIndex != *savedPeer) {
			return FlowAction::FlushAndReinsert;
		}

		m_exportData.peer[direction] = senderIndex;

		break;
	}
	case WireguardPacketType::HANDSHAKE_RESPONSE: {
		m_exportData.peer[direction] = senderIndex;

		constexpr std::size_t dstPeerOffset = 8;
		m_exportData.peer[static_cast<Direction>(!direction)] 
			= ntohl(*reinterpret_cast<const uint32_t*>(payload.data() + dstPeerOffset));

		break;
	}
	case WireguardPacketType::COOCKIE_REPLY: [[fallthrough]];
	case WireguardPacketType::TRANSPORT_DATA:
		m_exportData.peer[direction] = senderIndex;
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
		m_exportData.confidence = 1;
		return FlowAction::RequestNoData;
	}
	m_exportData.confidence = 100;

	return FlowAction::RequestTrimmedData;
}

ProcessPlugin* WireguardPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<WireguardPlugin*>(constructAtAddress), *this);
}

std::string WireguardPlugin::getName() const {
	return wireguardPluginManifest.name; 
}

const void* WireguardPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<WireguardPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	wireguardRegistrar(wireguardPluginManifest);

} // namespace ipxp
