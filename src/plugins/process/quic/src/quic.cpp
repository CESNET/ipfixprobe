/**
 * @file
 * @brief Plugin for parsing QUIC traffic.
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses QUIC traffic and extracts various QUIC fields,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "quic.hpp"

#include "quicGetters.hpp"
#include "quicHeaderView.hpp"
#include "quicInitialHeaderView.hpp"
#include "quicParser.hpp"
#include "quicTypesCumulative.hpp"

#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::quic {

static const PluginManifest quicPluginManifest = {
	.name = "quic",
	.description = "Quic process plugin for parsing quic traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("quic", "Parse QUIC traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createQUICSchema(FieldManager& fieldManager, FieldHandlers<QUICFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("quic");

	handlers.insert(QUICFields::QUIC_SNI, schema.addScalarField("QUIC_SNI", getQUICSNIField));

	handlers.insert(
		QUICFields::QUIC_USER_AGENT,
		schema.addScalarField("QUIC_USER_AGENT", getQUICUserAgentField));

	handlers.insert(
		QUICFields::QUIC_VERSION,
		schema.addScalarField("QUIC_VERSION", getQUICVersionField));

	handlers.insert(
		QUICFields::QUIC_CLIENT_VERSION,
		schema.addScalarField("QUIC_CLIENT_VERSION", getQUICClientVersionField));

	handlers.insert(
		QUICFields::QUIC_TOKEN_LENGTH,
		schema.addScalarField("QUIC_TOKEN_LENGTH", getQUICTokenLengthField));

	handlers.insert(QUICFields::QUIC_OCCID, schema.addScalarField("QUIC_OCCID", getQUICOCCIDField));

	handlers.insert(
		QUICFields::QUIC_OSCID,
		schema.addScalarField("QUIC_OSCID", getQUICOSCCIDField));

	handlers.insert(QUICFields::QUIC_SCID, schema.addScalarField("QUIC_SCID", getQUICSCIDField));

	handlers.insert(
		QUICFields::QUIC_RETRY_SCID,
		schema.addScalarField("QUIC_RETRY_SCID", getQUICRetrySCIDField));

	handlers.insert(
		QUICFields::QUIC_MULTIPLEXED,
		schema.addScalarField("QUIC_MULTIPLEXED", getQUICMultiplexedField));

	handlers.insert(
		QUICFields::QUIC_ZERO_RTT,
		schema.addScalarField("QUIC_ZERO_RTT", getQUICZeroRTTField));

	handlers.insert(
		QUICFields::QUIC_SERVER_PORT,
		schema.addScalarField("QUIC_SERVER_PORT", getQUICServerPortField));

	/*handlers.insert(
		QUICFields::QUIC_PACKETS,
		schema.addVectorField("QUIC_PACKETS", getQUICPacketsField));*/

	handlers.insert(
		QUICFields::QUIC_CH_PARSED,
		schema.addScalarField("QUIC_CH_PARSED", getQUICCHParsedField));

	/*handlers.insert(
		QUICFields::QUIC_TLS_EXT_TYPE,
		schema.addVectorField("QUIC_TLS_EXT_TYPE", getQUICTLSExtTypeField));

	handlers.insert(
		QUICFields::QUIC_TLS_EXT_LEN,
		schema.addVectorField("QUIC_TLS_EXT_LEN", getQUICTLSExtLenField));*/

	handlers.insert(
		QUICFields::QUIC_TLS_EXT,
		schema.addScalarField("QUIC_TLS_EXT", getQUICTLSExtField));

	return schema;
}

QUICPlugin::QUICPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createQUICSchema(manager, m_fieldHandlers);
}

constexpr static void copyFromIfNotEmptyTo(const auto& source, auto& destination) noexcept
{
	if (source.empty()) {
		return;
	}

	if (!destination.empty()) {
		return;
	}

	std::ranges::copy(
		source | std::views::take(destination.capacity()),
		std::back_inserter(destination));
}

constexpr void QUICPlugin::tryToSetOCCIDandSCID(
	const QUICDirection quicDirection,
	std::span<const uint8_t> sourceConnectionId,
	std::span<const uint8_t> destinationConnectionId,
	QUICContext& quicContext) noexcept
{
	DirectionalField<std::span<const uint8_t>> currentIds;
	currentIds[static_cast<bool>(QUICDirection::CLIENT_TO_SERVER)] = destinationConnectionId;
	currentIds[static_cast<bool>(QUICDirection::SERVER_TO_CLIENT)] = sourceConnectionId;

	const ConnectionId& serverId = quicContext.processingState.temporalCIDStorage.getSourceCID();
	copyFromIfNotEmptyTo(serverId, quicContext.originalServerId);
	copyFromIfNotEmptyTo(
		currentIds[static_cast<bool>(quicDirection)],
		quicContext.originalServerId);

	const ConnectionId& originalClientId
		= quicContext.processingState.temporalCIDStorage.getClientCID();
	copyFromIfNotEmptyTo(originalClientId, quicContext.originalClientId);
	copyFromIfNotEmptyTo(
		currentIds[!static_cast<bool>(quicDirection)],
		quicContext.originalClientId);
}

void QUICPlugin::processInitial(
	const std::optional<QUICDirection> quicDirection,
	const Direction flowDirection,
	const QUICHeaderView& headerView,
	const QUICInitialHeaderView& initialHeaderView,
	QUICContext& quicContext) noexcept
{
	quicContext.processingState.initialConnectionId = ConnectionId();
	quicContext.processingState.initialConnectionId->assign(
		initialHeaderView.destinationConnectionId.begin(),
		initialHeaderView.destinationConnectionId.end());
	if (quicDirection.has_value()
		&& !setConnectionIds(
			*quicDirection,
			flowDirection,
			initialHeaderView.sourceConnectionId,
			initialHeaderView.destinationConnectionId,
			quicContext)) {
		return;
	}

	if (initialHeaderView.tlsHandshake.type != TLSHandshake::Type::CLIENT_HELLO) {
		return;
	}

	if (initialHeaderView.tokenLength.has_value()) {
		quicContext.quicTokenLength = *initialHeaderView.tokenLength;
	}

	if (initialHeaderView.tokenLength.has_value() && *initialHeaderView.tokenLength > 0
		&& std::ranges::equal(
			//	????	m_exportData.retrySourceId, m_exportData.destinationConnectionId)) {
			quicContext.retrySourceId,
			initialHeaderView.destinationConnectionId)) {
		return;
	}

	const bool hasMultiplexing = (std::ranges::equal(
									  quicContext.originalServerId,
									  initialHeaderView.destinationConnectionId)
								  || std::ranges::equal(
									  //		????	m_exportData.sourceCID,
									  // initialHeaderView.destinationConnectionId)) &&
									  quicContext.originalClientId,
									  initialHeaderView.destinationConnectionId))
		&& initialHeaderView.serverName.has_value()
		&& std::ranges::equal(quicContext.serverName, *initialHeaderView.serverName);
	if (hasMultiplexing) {
		quicContext.multiplexedCount = std::min<uint16_t>(
			quicContext.multiplexedCount + 1,
			std::numeric_limits<uint8_t>::max());
		return;
	}

	if (initialHeaderView.userAgent.has_value()) {
		quicContext.userAgent = *initialHeaderView.userAgent;
	}
	// if (m_exportData.quicVersion == 0 ) {
	quicContext.quicVersion = static_cast<uint32_t>(headerView.version->id);
	//}

	copyFromIfNotEmptyTo(initialHeaderView.destinationConnectionId, quicContext.originalServerId);
	copyFromIfNotEmptyTo(initialHeaderView.sourceConnectionId, quicContext.originalClientId);

	copyFromIfNotEmptyTo(initialHeaderView.extensionTypes, quicContext.tlsExtensionTypes);
	copyFromIfNotEmptyTo(initialHeaderView.extensionLengths, quicContext.tlsExtensionLengths);

	quicContext.extensionsPayload = std::move(initialHeaderView.extensionsPayload);
}

constexpr void QUICPlugin::parseRetry(
	std::span<const uint8_t> sourceConnectionId,
	std::span<const uint8_t> destinationConnectionId,
	QUICContext& quicContext) noexcept
{
	quicContext.processingState.retryPacketCount++;
	if (quicContext.processingState.retryPacketCount != 1) {
		return;
	}
	/*
	 * A client MUST accept and process at most one Retry packet for each connection
	 * attempt. After the client has received and processed an Initial or Retry packet from
	 * the server, it MUST discard any subsequent Retry packets that it receives.
	 */
	// Additionally set token len
	quicContext.retrySourceId.assign(sourceConnectionId.begin(), sourceConnectionId.end());
	quicContext.processingState.initialConnectionId = ConnectionId();
	quicContext.processingState.initialConnectionId->assign(
		destinationConnectionId.begin(),
		destinationConnectionId.end());
	quicContext.quicTokenLength = 16; // ?????????

	copyFromIfNotEmptyTo(destinationConnectionId, quicContext.originalClientId);
}

constexpr static QUICHeaderView::PacketType
getMostSignificantPacketType(const QUICTypesCumulative packetTypesCumulative) noexcept
{
	if (packetTypesCumulative.bitfields.versionNegotiation) {
		return QUICHeaderView::PacketType::VERSION_NEGOTIATION;
	}
	if (packetTypesCumulative.bitfields.initial) {
		return QUICHeaderView::PacketType::INITIAL;
	}
	if (packetTypesCumulative.bitfields.retry) {
		return QUICHeaderView::PacketType::RETRY;
	}
	if (packetTypesCumulative.bitfields.zeroRTT) {
		return QUICHeaderView::PacketType::ZERO_RTT;
	}
	if (packetTypesCumulative.bitfields.handshake) {
		return QUICHeaderView::PacketType::HANDSHAKE;
	}

	__builtin_unreachable();
}

constexpr bool QUICPlugin::setConnectionIds(
	const std::optional<QUICDirection> quicDirection,
	const Direction flowDirection,
	std::span<const uint8_t> sourceConnectionId,
	std::span<const uint8_t> destinationConnectionId,
	QUICContext& quicContext) noexcept
{
	if (!quicDirection.has_value()) {
		quicContext.processingState.temporalCIDStorage.storeConnectionIds(
			flowDirection,
			sourceConnectionId,
			destinationConnectionId);
		return false;
	}
	tryToSetOCCIDandSCID(*quicDirection, sourceConnectionId, destinationConnectionId, quicContext);
	return true;
}

OnUpdateResult QUICPlugin::parseQUIC(
	FlowRecord& flowRecord,
	const QUICParser& quicParser,
	Direction packetDirection,
	QUICContext& quicContext) noexcept
{
	// Regardless the result push the type cumulative
	if (quicContext.packetTypes.size() != quicContext.packetTypes.capacity()) {
		quicContext.packetTypes.push_back(
			static_cast<uint8_t>(quicParser.packetTypesCumulative.raw));
	}

	if (quicParser.packetTypesCumulative.bitfields.zeroRTT) {
		quicContext.quicVersion = static_cast<uint32_t>(quicParser.headerView->version->id);
		quicContext.quicZeroRTTCount = std::min<uint16_t>(
			quicContext.quicZeroRTTCount + quicParser.zeroRTTPackets,
			std::numeric_limits<uint8_t>::max());
	}

	if (quicParser.initialHeaderView.has_value()) {
		quicContext.clientHelloParsed = quicParser.initialHeaderView->clientHelloParsed;
	}

	if (!quicContext.processingState.temporalCIDStorage.directionIsRevealed()
		&& quicParser.quicDirection.has_value()) {
		quicContext.processingState.temporalCIDStorage.pairDirections(
			*quicParser.quicDirection,
			packetDirection);
	}

	switch (getMostSignificantPacketType(quicParser.packetTypesCumulative)) {
	case QUICHeaderView::PacketType::VERSION_NEGOTIATION: {
		setConnectionIds(
			quicParser.quicDirection,
			packetDirection,
			quicParser.headerView->sourceConnectionId,
			quicParser.headerView->destinationConnectionId,
			quicContext);
		return OnUpdateResult::FlushFlow;
	}
	case QUICHeaderView::PacketType::INITIAL: {
		processInitial(
			quicParser.quicDirection,
			packetDirection,
			*quicParser.headerView,
			*quicParser.initialHeaderView,
			quicContext);
		break;
	}
	case QUICHeaderView::PacketType::HANDSHAKE: {
		setConnectionIds(
			quicParser.quicDirection,
			packetDirection,
			quicParser.headerView->sourceConnectionId,
			quicParser.headerView->destinationConnectionId,
			quicContext);
		break;
	}
	case QUICHeaderView::PacketType::RETRY: {
		parseRetry(
			quicParser.headerView->sourceConnectionId,
			quicParser.headerView->destinationConnectionId,
			quicContext);
		break;
	}
	case QUICHeaderView::PacketType::ZERO_RTT:
		// Connection IDs are identical to Client Initial CH. The DCID might be OSCID at first
		// and change to SCID later. We ignore the DCID.
		if (quicContext.originalClientId.empty()) {
			quicContext.originalClientId.assign(
				quicParser.headerView->sourceConnectionId.begin(),
				quicParser.headerView->sourceConnectionId.end());
		}
		break;
	}

	return OnUpdateResult::NeedsUpdate;
}

OnInitResult QUICPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	QUICParser quicParser;
	const bool quicParsed = quicParser.parse(
		getPayload(*flowContext.packetContext.packet),
		std::nullopt,
		flowContext.flowRecord.flowKey.l4Protocol);
	if (!quicParsed) {
		return OnInitResult::Irrelevant;
	}

	auto& quicContext = *std::construct_at(reinterpret_cast<QUICContext*>(pluginContext));
	const OnUpdateResult updateRequirement
		= parseQUIC(flowContext.flowRecord, quicParser, flowContext.packetDirection, quicContext);
	return updateRequirement == OnUpdateResult::NeedsUpdate ? OnInitResult::ConstructedNeedsUpdate
															: OnInitResult::ConstructedFinal;
}

OnUpdateResult QUICPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& quicContext = *reinterpret_cast<QUICContext*>(pluginContext);
	QUICParser quicParser;
	const bool quicParsed = quicParser.parse(
		getPayload(*flowContext.packetContext.packet),
		quicContext.processingState.initialConnectionId,
		flowContext.flowRecord.flowKey.l4Protocol);
	if (!quicParsed) {
		return OnUpdateResult::Remove;
	}

	return parseQUIC(flowContext.flowRecord, quicParser, flowContext.packetDirection, quicContext);
}

void QUICPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<QUICContext*>(pluginContext));
}

PluginDataMemoryLayout QUICPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(QUICContext),
		.alignment = alignof(QUICContext),
	};
}

static const PluginRegistrar<
	QUICPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	quicRegistrar(quicPluginManifest);

} // namespace ipxp::process::quic
