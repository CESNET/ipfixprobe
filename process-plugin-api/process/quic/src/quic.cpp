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

#include "quic.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

namespace ipxp {

static const PluginManifest quicPluginManifest = {
	.name = "quic",
	.description = "Quic process plugin for parsing quic traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("quic", "Parse QUIC traffic");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<QUICFields>> fields = {
	{QUICFields::QUIC_SNI, "QUIC_SNI"},
	{QUICFields::QUIC_USER_AGENT, "QUIC_USER_AGENT"},
	{QUICFields::QUIC_VERSION, "QUIC_VERSION"},
	{QUICFields::QUIC_CLIENT_VERSION, "QUIC_CLIENT_VERSION"},
	{QUICFields::QUIC_TOKEN_LENGTH, "QUIC_TOKEN_LENGTH"},
	{QUICFields::QUIC_OCCID, "QUIC_OCCID"},
	{QUICFields::QUIC_OSCID, "QUIC_OSCID"},
	{QUICFields::QUIC_SCID, "QUIC_SCID"},
	{QUICFields::QUIC_RETRY_SCID, "QUIC_RETRY_SCID"},
	{QUICFields::QUIC_MULTIPLEXED, "QUIC_MULTIPLEXED"},
	{QUICFields::QUIC_ZERO_RTT, "QUIC_ZERO_RTT"},
	{QUICFields::QUIC_SERVER_PORT, "QUIC_SERVER_PORT"},
	{QUICFields::QUIC_PACKETS, "QUIC_PACKETS"},
	{QUICFields::QUIC_CH_PARSED, "QUIC_CH_PARSED"},
	{QUICFields::QUIC_TLS_EXT_TYPE, "QUIC_TLS_EXT_TYPE"},
	{QUICFields::QUIC_TLS_EXT_LEN, "QUIC_TLS_EXT_LEN"},
	{QUICFields::QUIC_TLS_EXT, "QUIC_TLS_EXT"},
};


static FieldSchema createQUICSchema()
{
	FieldSchema schema("quic");

	// TODO ADD EXPORT FIELDS

	return schema;
}

QUICPlugin::QUICPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createQUICSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

constexpr static
void copyFromIfNotEmptyTo(
	const auto& source,
	auto& destination) noexcept
{
	if (source.empty()) {
		return;
	}

	if (!destination.empty()) {
		return;
	}

	std::ranges::copy(source | 
		std::views::take(destination.capacity()),
		std::back_inserter(destination));
}

constexpr
void QUICPlugin::tryToSetOCCIDandSCID(
	const QUICDirection quicDirection,
	std::span<const uint8_t> sourceConnectionId,
	std::span<const uint8_t> destinationConnectionId
) noexcept
{
	const DirectionalField<std::span<const uint8_t>> currentIds;
	currentIds[QUICDirection::CLIENT_TO_SERVER] = destinationConnectionId;
	currentIds[QUICDirection::SERVER_TO_CLIENT] = sourceConnectionId;

	ConnectionId serverId = m_temporalCIDStorage.getServerCID(quicDirection);
	copyFromIfNotEmptyTo(serverId, m_exportData.serverConnectionId);
	copyFromIfNotEmptyTo(
		currentIds[quicDirection], m_exportData.serverConnectionId);
	
	ConnectionId originalClientId = m_temporalCIDStorage.getClientCID(quicDirection);
	copyFromIfNotEmptyTo(originalClientId, m_exportData.clientConnectionId);
	copyFromIfNotEmptyTo(
		currentIds[!quicDirection], m_exportData.clientConnectionId);
}

constexpr
void QUICPlugin::processInitial(
	const Direction flowDirection,
	const HeaderView& headerView,
	const InitialHeaderView& initialHeaderView,
	std::optional<QUICDirection> quicDirection) noexcept
{
	m_initialConnectionId = initialHeaderView.destinationConnectionId;
	if (!setConnectionIds(...)) {
		return;
	}

	if (initialHeaderView.tlsHandshake.type != TLSHeader::Type::CLIENT_HELLO) {
		return;
	}

	if (initialHeaderView.tokenLength.has_value()) {
		m_exportData.tokenLength = *initialHeaderView.tokenLength;
	}

	if (initialHeaderView.tokenLength.has_value() &&
		*initialHeaderView.tokenLength > 0 &&
		std::ranges::equal(
			m_exportData.retrySCID, m_exportData.destinationConnectionId)) {
		return;
	}

	//process multiplexing
	const bool hasMultiplexing =
		(std::ranges::equal(m_exportData.serverCID, destinationConnectionId) ||
			std::ranges::equal(m_exportData.sourceCID, destinationConnectionId)) &&
		std::ranges::equal(m_exportData.sni, initialHeaderView.sni);
	if (hasMultiplexing) {
		m_exportData.multiplexedCount = std::min<uint16_t>(
			m_exportData.multiplexedCount + 1, std::numeric_limits<uint8_t>::max());
		return;
	}

	m_exportData.userAgent = initialHeaderView.userAgent;
	//if (m_exportData.quicVersion == 0 ) {
	m_exportData.quicVersion = headerView.versionId;
	//}

	copyFromIfNotEmptyTo(destinationConnectionId, m_exportData.serverCID);
	copyFromIfNotEmptyTo(sourceConnectionId, m_exportData.clientCID);

	copyFromIfNotEmptyTo(
		initialHeaderView.extensionTypes, m_exportData.tlsExtensionTypes);
	copyFromIfNotEmptyTo(
		initialHeaderView.extensionLengths, m_exportData.tlsExtensionLengths);
	
	m_exportData.extensionsPayload = std::move(initialHeaderView.extensionsPayload);
}

constexpr
void QUICPlugin::parseRetry() noexcept
{
	m_retryPacketCount++;
	if (m_retryPacketCount != 1) {
		return;
	}
	/*
	* A client MUST accept and process at most one Retry packet for each connection
	* attempt. After the client has received and processed an Initial or Retry packet from
	* the server, it MUST discard any subsequent Retry packets that it receives.
	*/
	// Additionally set token len
	m_exportData.retryCID = sourceConnectionId;
	m_initialCID = destinationConnectionId;
	m_exportData.tokenLength = 16; // ?????????

	copyFromIfNotEmptyTo(destinationConnectionId, m_exportData.clientCID);
}

constexpr static
PacketType getMostSignificantPacketType(
	const QUICTypesCumulative packetTypesCumulative) noexcept
{
	if (packetTypesCumulative.bits.versionNegotiation) {
		return QUICHeaderView::PacketType::VERSION_NEGOTIATION;
	}
	if (packetTypesCumulative.bits.initial) {
		return QUICHeaderView::PacketType::INITIAL;
	}
	if (packetTypesCumulative.bits.retry) {
		return QUICHeaderView::PacketType::RETRY;
	}
	if (packetTypesCumulative.bits.zeroRTT) {
		return QUICHeaderView::PacketType::ZERO_RTT;
	}
	if (packetTypesCumulative.bits.handshake) {
		return QUICHeaderView::PacketType::HANDSHAKE;
	}

	return 0;
}

constexpr
bool QUICPlugin::setConnectionIds(
	const QUICDirection quicDirection,
	const Direction flowDirection,
	std::span<const uint8_t> sourceConnectionId,
	std::span<const uint8_t> destinationConnectionId
) noexcept
{
	if (!quicDirection.has_value()) {
		m_temporalCIDStorage.storeConnectionIds(
			flowDirection, 
			sourceConnectionId, 
			destinationConnectionId);
		return false;
	}
	tryToSetOCCIDandSCID(...);
	return true;
}

FlowAction QUICPlugin::parseQUIC()
{
	QUICParser quicParser;

	const bool quicParsed = quicParser.parse(payload, initialDestConnectionId);
	
	// Regardless the result push the type cumulative
	if (!m_exportData.packets.full()) {
		m_exportData.packets.push_back(
			static_cast<uint8_t>(quicParser.packetTypesCumulative.raw));
	}
	
	if (!quicParsed) {
		return FlowAction::RequestNoData;
	}

	if (quicParser.packetTypesCumulative.bits.zeroRTT) {
		m_exportData.version = quicParser.headerView->versionId;
		m_exportData.zeroRTTPacket = std::min<uint16_t>(
			m_exportData.zeroRTTPacket + quicParser.zeroRTTPackets,
			std::numeric_limits<uint8_t>::max()
		);
	}

	if (quicParser.initialHeaderView.has_value()) {
		m_exportData.clientHelloParsed 
			= quicParser.initialHeaderView->clientHelloParsed;
	}
	

	if (!m_temporalCIDStorage.directionIsRevealed() && 
		quicParser.quicDirection.has_value()) {
		m_temporalCIDStorage.pairDirections(
			*quicParser.quicDirection, packet.direction);
	}

	switch (getMostSignificantPacketType(
		quicParser.packetTypesCumulative)) {
	case QUICParser::PACKET_TYPE::VERSION_NEGOTIATION: {
		setConnectionIds(...);
		return FlowAction::Flush;
	}
	case QUICParser::PACKET_TYPE::INITIAL: {
		processInitial(...);
		break;
	}
	case QUICParser::PACKET_TYPE::HANDSHAKE:{ 
		setConnectionIds(...);
		break;
	}
	case QUICParser::PACKET_TYPE::RETRY: {
		parseRetry(...);
		break;
	}
	case QUICParser::PACKET_TYPE::ZERO_RTT:
		// Connection IDs are identical to Client Initial CH. The DCID might be OSCID at first
		// and change to SCID later. We ignore the DCID.
		if (m_exportData.clientCID.empty()) {
			m_exportData.clientCID = sourceConnectionId;
		}
		break;
	}

	return FlowAction::RequestFullData;
}

FlowAction QUICPlugin::onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
{
	return parseQUIC(flowRecord, packet);
}

FlowAction QUICPlugin::onFlowUpdate(FlowRecord& flowRecord, const Packet& packet)
{
	return parseQUIC(flowRecord, packet);
}

void QUICPlugin::onFlowExport(FlowRecord& flowRecord) {
	// empty
}

ProcessPlugin* QUICPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<QUICPlugin*>(constructAtAddress), *this);
}

std::string QUICPlugin::getName() const { 
	return quicPluginManifest.name; 
}

const void* QUICPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<QUICPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	quicRegistrar(quicPluginManifest);

} // namespace ipxp
