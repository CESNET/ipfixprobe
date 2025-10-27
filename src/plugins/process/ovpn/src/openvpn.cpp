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

#include "openvpnGetters.hpp"
#include "openvpnOpcode.hpp"
#include "rtpHeader.hpp"

#include <iostream>

#include <amon/layers/TCP.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils/spanUtils.hpp>

namespace ipxp::process::ovpn {

static const PluginManifest ovpnPluginManifest = {
	.name = "ovpn",
	.description = "Ovpn process plugin for parsing ovpn traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("ovpn", "OpenVPN detector plugin");
			parser.usage(std::cout);
		},
};

static FieldGroup
createOpenVPNSchema(FieldManager& manager, FieldHandlers<OpenVPNFields>& handlers) noexcept
{
	FieldGroup schema = manager.createFieldGroup("ovpn");

	handlers.insert(
		OpenVPNFields::OVPN_CONF_LEVEL,
		schema.addScalarField("OVPN_CONF_LEVEL", getOVPNConfidenceLevelField));

	return schema;
}

OpenVPNPlugin::OpenVPNPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createOpenVPNSchema(manager, m_fieldHandlers);
}

static bool hasTLSClientHello(std::span<const std::byte> vpnPayload) noexcept
{
	constexpr std::size_t contentTypeOffset = 0;
	constexpr std::byte handshakeContentType = std::byte {0x16};

	constexpr std::size_t handshakeTypeOffset = 5;
	constexpr std::byte clientHelloHandshakeType = std::byte {0x1};

	constexpr std::size_t encryptedHeaderSize = 28;

	return (vpnPayload.size() > handshakeTypeOffset
			&& vpnPayload[contentTypeOffset] == handshakeContentType
			&& vpnPayload[handshakeTypeOffset] == clientHelloHandshakeType)
		|| (vpnPayload.size() > encryptedHeaderSize + handshakeTypeOffset
			&& vpnPayload[encryptedHeaderSize + contentTypeOffset] == handshakeContentType
			&& vpnPayload[encryptedHeaderSize + handshakeTypeOffset] == clientHelloHandshakeType);
}

constexpr static bool isValidRTPHeader(const amon::Packet& packet) noexcept
{
	auto tcp = getLayerView<amon::layers::TCPView>(packet, packet.layout.l4);
	if (!tcp.has_value())
		return false;

	const std::optional<std::size_t> ipPayloadLength = getIPPayloadLength(packet);
	if (!ipPayloadLength.has_value() || *ipPayloadLength < sizeof(RTPHeader))
		return false;

	const RTPHeader* rtpHeader = reinterpret_cast<const RTPHeader*>(getPayload(packet).data());

	if (rtpHeader->version != 2)
		return false;

	if (rtpHeader->payloadType >= 72 && rtpHeader->payloadType <= 95)
		return false;

	return true;
}

constexpr static std::optional<std::size_t> getOpcodeOffset(const uint8_t l4Protocol)
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

bool OpenVPNPlugin::updateConfidenceLevel(
	const amon::Packet& packet,
	const FlowRecord& flowRecord,
	const Direction direction,
	OpenVPNContext& openVPNContext) noexcept
{
	std::span<const std::byte> payload = getPayload(packet);
	if (payload.size() < 2) {
		return false;
	}

	const std::optional<std::size_t> ipPayloadLength = getIPPayloadLength(packet);
	if (!ipPayloadLength.has_value()) {
		return false;
	}

	const std::optional<std::size_t> opcodeOffset = getOpcodeOffset(flowRecord.flowKey.l4Protocol);
	if (!opcodeOffset.has_value()) {
		return false;
	}

	const OpenVPNOpcode opcode = static_cast<OpenVPNOpcode>(payload[*opcodeOffset]);

	constexpr std::size_t openvpnHeaderSize = 14;
	const bool hasClientHello = payload.size() > openvpnHeaderSize
		&& hasTLSClientHello(payload.subspan(openvpnHeaderSize));

	openVPNContext.processingState.processOpcode(
		opcode,
		direction ? flowRecord.flowKey.srcIp : flowRecord.flowKey.dstIp,
		direction ? flowRecord.flowKey.dstIp : flowRecord.flowKey.srcIp,
		hasClientHello,
		isValidRTPHeader(packet),
		*ipPayloadLength);

	return true;
}

OnInitResult OpenVPNPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto& openVPNContext = *reinterpret_cast<OpenVPNContext*>(pluginContext);
	if (!updateConfidenceLevel(
			*flowContext.packetContext.packet,
			flowContext.flowRecord,
			flowContext.packetDirection,
			openVPNContext)) {
		return OnInitResult::ConstructedFinal;
	}

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult OpenVPNPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& openVPNContext = *reinterpret_cast<OpenVPNContext*>(pluginContext);
	if (!updateConfidenceLevel(
			*flowContext.packetContext.packet,
			flowContext.flowRecord,
			flowContext.packetDirection,
			openVPNContext)) {
		return OnUpdateResult::Final;
	}

	return OnUpdateResult::NeedsUpdate;
}

OnExportResult OpenVPNPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	auto& openVPNContext = *reinterpret_cast<OpenVPNContext*>(pluginContext);
	// do not export ovpn for short flows, usually port scans
	const std::size_t packetsTotal = flowRecord.directionalData[Direction::Forward].packets
		+ flowRecord.directionalData[Direction::Reverse].packets;
	const std::optional<uint8_t> confidenceLevel
		= openVPNContext.processingState.getCurrentConfidenceLevel(packetsTotal);
	if (!confidenceLevel.has_value()) {
		return OnExportResult::Remove;
	}

	openVPNContext.vpnConfidence = *confidenceLevel;
	m_fieldHandlers[OpenVPNFields::OVPN_CONF_LEVEL].setAsAvailable(flowRecord);

	return OnExportResult::NoAction;
}

void OpenVPNPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<OpenVPNContext*>(pluginContext));
}

PluginDataMemoryLayout OpenVPNPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(OpenVPNContext),
		.alignment = alignof(OpenVPNContext),
	};
}

static const PluginRegistrar<
	OpenVPNPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ovpnRegistrar(ovpnPluginManifest);

} // namespace ipxp::process::ovpn
