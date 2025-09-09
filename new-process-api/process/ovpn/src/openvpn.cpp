/**
 * @file
 * @brief Plugin for parsing ovpn traffic.
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Martin Ctrnacty <ctrnama2@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that calculates confidence level that given flow is OpenVPN,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 * 
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "openvpn.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

#include "openvpnOpcode.hpp"
#include "rtpHeader.hpp"

namespace ipxp {


static const PluginManifest ovpnPluginManifest = {
	.name = "ovpn",
	.description = "Ovpn process plugin for parsing ovpn traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("ovpn", "OpenVPN detector plugin");
			parser.usage(std::cout);*/
		},
};

static FieldSchema createOpenVPNSchema(FieldManager& manager, FieldHandlers<OpenVPNFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("ovpn");

	handlers.insert(OpenVPNFields::OVPN_CONF_LEVEL, schema.addScalarField(
		"OVPN_CONF_LEVEL",
		[] (const void* context) { return reinterpret_cast<const OpenVPNData*>(context)->vpnConfidence; }
	));

	return schema;
}

OpenVPNPlugin::OpenVPNPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createOpenVPNSchema(manager, m_fieldHandlers);
}

static
bool hasTLSClientHello(std::span<const std::byte> vpnPayload) noexcept
{
	constexpr std::size_t contentTypeOffset = 0;
	constexpr std::byte handshakeContentType = std::byte{0x16};

	constexpr std::size_t handshakeTypeOffset = 5;
	constexpr std::byte clientHelloHandshakeType = std::byte{0x1};

	constexpr std::size_t encryptedHeaderSize = 28;

	return (vpnPayload.size() > handshakeTypeOffset 
		&& vpnPayload[contentTypeOffset] == handshakeContentType
		&& vpnPayload[handshakeTypeOffset] == clientHelloHandshakeType)
	|| (vpnPayload.size() > encryptedHeaderSize + handshakeTypeOffset 
		&& vpnPayload[encryptedHeaderSize + contentTypeOffset] == handshakeContentType
		&& vpnPayload[encryptedHeaderSize + handshakeTypeOffset] == clientHelloHandshakeType);
}

constexpr static
bool isValidRTPHeader(const Packet& packet)
{
	// TODO USE DISSECTOR VALUES
	if (packet.flowKey.l4Protocol != 17)
		return false;

	if (packet.payload.size() < sizeof(RTPHeader))
		return false;

	const RTPHeader* rtpHeader 
		= reinterpret_cast<const RTPHeader*>(packet.payload.data());

	if (rtpHeader->version != 2)
		return false;

	if (rtpHeader->payloadType >= 72 && rtpHeader->payloadType <= 95)
		return false;

	return true;
}

constexpr static
std::optional<std::size_t> getOpcodeOffset(const uint8_t l4Protocol)
{
	constexpr std::size_t UDP = 17;
	if (l4Protocol == UDP) {
		return 0;
	} 
	
	constexpr std::size_t TCP = 6;
	if (l4Protocol == TCP) {
		return 1;
	}

	return std::nullopt;
}

bool OpenVPNPlugin::updateConfidenceLevel(const Packet& packet, OpenVPNData& pluginData)
{
	// TODO USE VALUES FROM DISSECTOR 
	
	if (packet.payload.size() < 2) {
		return false;
	}

	const std::optional<std::size_t> opcodeOffset 
		= getOpcodeOffset(packet.flowKey.l4Protocol);
	if (!opcodeOffset.has_value()) {
		return false;
	}

	const OpenVPNOpcode opcode 
		= static_cast<OpenVPNOpcode>(packet.payload[*opcodeOffset]);

	constexpr std::size_t openvpnHeaderSize = 14;
	const bool hasClientHello = packet.payload.size() > openvpnHeaderSize
		&& hasTLSClientHello(packet.payload.subspan(openvpnHeaderSize));

	pluginData.processingState.processOpcode(opcode, 
		packet.flowKey.srcIp, packet.flowKey.dstIp, hasClientHello, 
		isValidRTPHeader(packet), packet.realLength);

	return true;
}

PluginInitResult OpenVPNPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<OpenVPNData*>(pluginContext));
	if (!updateConfidenceLevel(flowContext.packet, *pluginData)) {
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult OpenVPNPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<OpenVPNData*>(pluginContext);
	if (!updateConfidenceLevel(flowContext.packet, *pluginData)) {
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}
	
	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginExportResult OpenVPNPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<OpenVPNData*>(pluginContext);
	// do not export ovpn for short flows, usually port scans
	const std::size_t packetsTotal 
		= flowRecord.dataForward.packets + flowRecord.dataReverse.packets;
	const std::optional<uint8_t> confidenceLevel 
		= pluginData->processingState.getCurrentConfidenceLevel(packetsTotal);
	if (!confidenceLevel.has_value()) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	pluginData->vpnConfidence = *confidenceLevel;
	m_fieldHandlers[OpenVPNFields::OVPN_CONF_LEVEL].setAsAvailable(flowRecord);
}

void OpenVPNPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<OpenVPNData*>(pluginContext));
}

PluginDataMemoryLayout OpenVPNPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(OpenVPNData),
		.alignment = alignof(OpenVPNData),
	};
}

static const PluginRegistrar<OpenVPNPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ovpnRegistrar(ovpnPluginManifest);


} // namespace ipxp
