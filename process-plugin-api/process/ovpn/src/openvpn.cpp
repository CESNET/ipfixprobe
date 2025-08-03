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

const inline std::vector<FieldPair<OpenVPNFields>> fields = {
	{OpenVPNFields::OVPN_CONF_LEVEL, "OVPN_CONF_LEVEL"},
};


static FieldSchema createOpenVPNSchema()
{
	FieldSchema schema("ovpn");

	schema.addScalarField<uint8_t>(
		"OVPN_CONF_LEVEL",
		FieldDirection::DirectionalIndifferent,
		offsetof(OpenVPNExport, vpnConfidence));

	return schema;
}

OpenVPNPlugin::OpenVPNPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createOpenVPNSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
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

FlowAction OpenVPNPlugin::updateConfidenceLevel(const Packet& packet)
{
	// TODO USE VALUES FROM DISSECTOR 
	
	if (packet.payload.size() < 2) {
		return FlowAction::RequestNoData;
	}

	const std::optional<std::size_t> opcodeOffset 
		= getOpcodeOffset(packet.flowKey.l4Protocol);
	if (!opcodeOffset.has_value()) {
		return FlowAction::RequestNoData;
	}

	const OpenVPNOpcode opcode 
		= static_cast<OpenVPNOpcode>(packet.payload[*opcodeOffset]);

	constexpr std::size_t openvpnHeaderSize = 14;
	const bool hasClientHello = packet.payload.size() > openvpnHeaderSize
		&& hasTLSClientHello(packet.payload.subspan(openvpnHeaderSize));

	m_processingState.processOpcode(opcode, 
		packet.flowKey.srcIp, packet.flowKey.dstIp, hasClientHello, 
		isValidRTPHeader(packet), packet.realLength);

	return FlowAction::RequestFullData;
}

FlowAction OpenVPNPlugin::onFlowCreate([[maybe_unused]]FlowRecord& flowRecord, const Packet& packet)
{
	return updateConfidenceLevel(packet);
}

FlowAction OpenVPNPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord,
	const Packet& packet)
{
	return updateConfidenceLevel(packet);
}

void OpenVPNPlugin::onFlowExport(FlowRecord& flowRecord) {

	// do not export ovpn for short flows, usually port scans
	const std::size_t packetsTotal 
		= flowRecord.dataForward.packets + flowRecord.dataReverse.packets;
	const std::optional<uint8_t> confidenceLevel 
		= m_processingState.getCurrentConfidenceLevel(packetsTotal);
	if (!confidenceLevel.has_value()) {
		return;
	}

	m_exportData.vpnConfidence = *confidenceLevel;
	m_fieldHandlers[OpenVPNFields::OVPN_CONF_LEVEL].setAsAvailable(flowRecord);
}



ProcessPlugin* OpenVPNPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<OpenVPNPlugin*>(constructAtAddress), *this);
}

std::string OpenVPNPlugin::getName() const {
	return ovpnPluginManifest.name;
}

const void* OpenVPNPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<OpenVPNPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ovpnRegistrar(ovpnPluginManifest);


} // namespace ipxp
