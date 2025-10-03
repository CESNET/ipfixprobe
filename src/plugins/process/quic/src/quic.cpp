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

#include "quicHeaderView.hpp"
#include "quicInitialHeaderView.hpp"
#include "quicParser.hpp"
#include "quicTypesCumulative.hpp"

#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp {

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

	handlers.insert(
		QUICFields::QUIC_SNI,
		schema.addScalarField("QUIC_SNI", [](const void* context) {
			return toStringView(static_cast<const QUICData*>(context)->serverName);
		}));
	handlers.insert(
		QUICFields::QUIC_USER_AGENT,
		schema.addScalarField("QUIC_USER_AGENT", [](const void* context) {
			return toStringView(static_cast<const QUICData*>(context)->userAgent);
		}));
	handlers.insert(
		QUICFields::QUIC_VERSION,
		schema.addScalarField("QUIC_VERSION", [](const void* context) {
			return static_cast<const QUICData*>(context)->quicVersion;
		}));
	handlers.insert(
		QUICFields::QUIC_CLIENT_VERSION,
		schema.addScalarField("QUIC_CLIENT_VERSION", [](const void* context) {
			return static_cast<const QUICData*>(context)->quicClientVersion;
		}));
	handlers.insert(
		QUICFields::QUIC_TOKEN_LENGTH,
		schema.addScalarField("QUIC_TOKEN_LENGTH", [](const void* context) {
			return static_cast<const QUICData*>(context)->quicTokenLength;
		}));
	handlers.insert(
		QUICFields::QUIC_OCCID,
		schema.addScalarField("QUIC_OCCID", [](const void* context) {
			return toStringView(static_cast<const QUICData*>(context)->originalClientId);
		}));
	handlers.insert(
		QUICFields::QUIC_OSCID,
		schema.addScalarField("QUIC_OSCID", [](const void* context) {
			return toStringView(static_cast<const QUICData*>(context)->originalServerId);
		}));
	handlers.insert(
		QUICFields::QUIC_SCID,
		schema.addScalarField("QUIC_SCID", [](const void* context) {
			return toStringView(static_cast<const QUICData*>(context)->sourceId);
		}));
	handlers.insert(
		QUICFields::QUIC_RETRY_SCID,
		schema.addScalarField("QUIC_RETRY_SCID", [](const void* context) {
			return toStringView(static_cast<const QUICData*>(context)->retrySourceId);
		}));
	handlers.insert(
		QUICFields::QUIC_MULTIPLEXED,
		schema.addScalarField("QUIC_MULTIPLEXED", [](const void* context) {
			return static_cast<const QUICData*>(context)->multiplexedCount;
		}));
	handlers.insert(
		QUICFields::QUIC_ZERO_RTT,
		schema.addScalarField("QUIC_ZERO_RTT", [](const void* context) {
			return static_cast<const QUICData*>(context)->quicZeroRTTCount;
		}));
	handlers.insert(
		QUICFields::QUIC_SERVER_PORT,
		schema.addScalarField("QUIC_SERVER_PORT", [](const void* context) {
			return static_cast<const QUICData*>(context)->serverPort;
		}));
	// TODO FIX
	/*handlers.insert(QUICFields::QUIC_PACKETS, schema.addVectorField(
		"QUIC_PACKETS",
		[](const void* context) { return toSpan<const uint8_t>(static_cast<const
	QUICData*>(context)->packetTypes); }
	));*/
	handlers.insert(
		QUICFields::QUIC_CH_PARSED,
		schema.addScalarField("QUIC_CH_PARSED", [](const void* context) {
			return static_cast<const QUICData*>(context)->clientHelloParsed;
		}));
	/*handlers.insert(QUICFields::QUIC_TLS_EXT_TYPE, schema.addVectorField(
		"QUIC_TLS_EXT_TYPE",
		[](const void* context) { return toSpan<const uint16_t>(static_cast<const
	QUICData*>(context)->tlsExtensionTypes); }
	));
	handlers.insert(QUICFields::QUIC_TLS_EXT_LEN, schema.addVectorField(
		"QUIC_TLS_EXT_LEN",
		[](const void* context) { return toSpan<const uint16_t>(static_cast<const
	QUICData*>(context)->tlsExtensionLengths); }
	));*/
	handlers.insert(
		QUICFields::QUIC_TLS_EXT,
		schema.addScalarField("QUIC_TLS_EXT", [](const void* context) {
			return toStringView(static_cast<const QUICData*>(context)->extensionsPayload);
		}));

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
	QUICData& pluginData) noexcept
{
	DirectionalField<std::span<const uint8_t>> currentIds;
	currentIds[static_cast<bool>(QUICDirection::CLIENT_TO_SERVER)] = destinationConnectionId;
	currentIds[static_cast<bool>(QUICDirection::SERVER_TO_CLIENT)] = sourceConnectionId;

	const ConnectionId& serverId = pluginData.processingState.temporalCIDStorage.getSourceCID();
	copyFromIfNotEmptyTo(serverId, pluginData.originalServerId);
	copyFromIfNotEmptyTo(currentIds[static_cast<bool>(quicDirection)], pluginData.originalServerId);

	const ConnectionId& originalClientId
		= pluginData.processingState.temporalCIDStorage.getClientCID();
	copyFromIfNotEmptyTo(originalClientId, pluginData.originalClientId);
	copyFromIfNotEmptyTo(
		currentIds[!static_cast<bool>(quicDirection)],
		pluginData.originalClientId);
}

void QUICPlugin::processInitial(
	const std::optional<QUICDirection> quicDirection,
	const Direction flowDirection,
	const QUICHeaderView& headerView,
	const QUICInitialHeaderView& initialHeaderView,
	QUICData& pluginData) noexcept
{
	pluginData.processingState.initialConnectionId.assign(
		initialHeaderView.destinationConnectionId.begin(),
		initialHeaderView.destinationConnectionId.end());
	if (quicDirection.has_value()
		&& !setConnectionIds(
			*quicDirection,
			flowDirection,
			initialHeaderView.sourceConnectionId,
			initialHeaderView.destinationConnectionId,
			pluginData)) {
		return;
	}

	if (initialHeaderView.tlsHandshake.type != TLSHandshake::Type::CLIENT_HELLO) {
		return;
	}

	if (initialHeaderView.tokenLength.has_value()) {
		pluginData.quicTokenLength = *initialHeaderView.tokenLength;
	}

	if (initialHeaderView.tokenLength.has_value() && *initialHeaderView.tokenLength > 0
		&& std::ranges::equal(
			//	????	m_exportData.retrySourceId, m_exportData.destinationConnectionId)) {
			pluginData.retrySourceId,
			initialHeaderView.destinationConnectionId)) {
		return;
	}

	const bool hasMultiplexing = (std::ranges::equal(
									  pluginData.originalServerId,
									  initialHeaderView.destinationConnectionId)
								  || std::ranges::equal(
									  //		????	m_exportData.sourceCID,
									  // initialHeaderView.destinationConnectionId)) &&
									  pluginData.originalServerId,
									  initialHeaderView.destinationConnectionId))
		&& initialHeaderView.serverName.has_value()
		&& std::ranges::equal(pluginData.serverName, *initialHeaderView.serverName);
	if (hasMultiplexing) {
		pluginData.multiplexedCount = std::min<uint16_t>(
			pluginData.multiplexedCount + 1,
			std::numeric_limits<uint8_t>::max());
		return;
	}

	if (initialHeaderView.userAgent.has_value()) {
		pluginData.userAgent = *initialHeaderView.userAgent;
	}
	// if (m_exportData.quicVersion == 0 ) {
	pluginData.quicVersion = static_cast<uint32_t>(headerView.version->id);
	//}

	copyFromIfNotEmptyTo(initialHeaderView.destinationConnectionId, pluginData.originalServerId);
	copyFromIfNotEmptyTo(initialHeaderView.sourceConnectionId, pluginData.originalClientId);

	copyFromIfNotEmptyTo(initialHeaderView.extensionTypes, pluginData.tlsExtensionTypes);
	copyFromIfNotEmptyTo(initialHeaderView.extensionLengths, pluginData.tlsExtensionLengths);

	pluginData.extensionsPayload = std::move(initialHeaderView.extensionsPayload);
}

constexpr void QUICPlugin::parseRetry(
	std::span<const uint8_t> sourceConnectionId,
	std::span<const uint8_t> destinationConnectionId,
	QUICData& pluginData) noexcept
{
	pluginData.processingState.retryPacketCount++;
	if (pluginData.processingState.retryPacketCount != 1) {
		return;
	}
	/*
	 * A client MUST accept and process at most one Retry packet for each connection
	 * attempt. After the client has received and processed an Initial or Retry packet from
	 * the server, it MUST discard any subsequent Retry packets that it receives.
	 */
	// Additionally set token len
	pluginData.retrySourceId.assign(sourceConnectionId.begin(), sourceConnectionId.end());
	pluginData.processingState.initialConnectionId.assign(
		destinationConnectionId.begin(),
		destinationConnectionId.end());
	pluginData.quicTokenLength = 16; // ?????????

	copyFromIfNotEmptyTo(destinationConnectionId, pluginData.originalClientId);
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
	QUICData& pluginData) noexcept
{
	if (!quicDirection.has_value()) {
		pluginData.processingState.temporalCIDStorage.storeConnectionIds(
			flowDirection,
			sourceConnectionId,
			destinationConnectionId);
		return false;
	}
	tryToSetOCCIDandSCID(*quicDirection, sourceConnectionId, destinationConnectionId, pluginData);
	return true;
}

PluginUpdateResult QUICPlugin::parseQUIC(
	FlowRecord& flowRecord,
	const QUICParser& quicParser,
	Direction packetDirection,
	QUICData& pluginData) noexcept
{
	// Regardless the result push the type cumulative
	if (pluginData.packetTypes.size() != pluginData.packetTypes.capacity()) {
		pluginData.packetTypes.push_back(
			static_cast<uint8_t>(quicParser.packetTypesCumulative.raw));
	}

	if (quicParser.packetTypesCumulative.bitfields.zeroRTT) {
		pluginData.quicVersion = static_cast<uint32_t>(quicParser.headerView->version->id);
		pluginData.quicZeroRTTCount = std::min<uint16_t>(
			pluginData.quicZeroRTTCount + quicParser.zeroRTTPackets,
			std::numeric_limits<uint8_t>::max());
	}

	if (quicParser.initialHeaderView.has_value()) {
		pluginData.clientHelloParsed = quicParser.initialHeaderView->clientHelloParsed;
	}

	if (!pluginData.processingState.temporalCIDStorage.directionIsRevealed()
		&& quicParser.quicDirection.has_value()) {
		pluginData.processingState.temporalCIDStorage.pairDirections(
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
			pluginData);
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::Flush,
		};
	}
	case QUICHeaderView::PacketType::INITIAL: {
		processInitial(
			quicParser.quicDirection,
			packetDirection,
			*quicParser.headerView,
			*quicParser.initialHeaderView,
			pluginData);
		break;
	}
	case QUICHeaderView::PacketType::HANDSHAKE: {
		setConnectionIds(
			quicParser.quicDirection,
			packetDirection,
			quicParser.headerView->sourceConnectionId,
			quicParser.headerView->destinationConnectionId,
			pluginData);
		break;
	}
	case QUICHeaderView::PacketType::RETRY: {
		parseRetry(
			quicParser.headerView->sourceConnectionId,
			quicParser.headerView->destinationConnectionId,
			pluginData);
		break;
	}
	case QUICHeaderView::PacketType::ZERO_RTT:
		// Connection IDs are identical to Client Initial CH. The DCID might be OSCID at first
		// and change to SCID later. We ignore the DCID.
		if (pluginData.originalClientId.empty()) {
			pluginData.originalClientId.assign(
				quicParser.headerView->sourceConnectionId.begin(),
				quicParser.headerView->sourceConnectionId.end());
		}
		break;
	}

	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginInitResult QUICPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	QUICParser quicParser;
	const bool quicParsed = quicParser.parse(
		toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len),
		// pluginData.processingState.initialConnectionId,
		ConnectionId(), // TODO FIX
		flowContext.flowRecord.flowKey.l4Protocol);
	if (!quicParsed) {
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<QUICData*>(pluginContext));
	auto [updateRequirement, flowAction]
		= parseQUIC(flowContext.flowRecord, quicParser, flowContext.packet.source_pkt, *pluginData);
	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = updateRequirement,
		.flowAction = flowAction,
	};
}

PluginUpdateResult QUICPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<QUICData*>(pluginContext);
	QUICParser quicParser;
	const bool quicParsed = quicParser.parse(
		toSpan<const std::byte>(flowContext.packet.payload, flowContext.packet.payload_len),
		pluginData->processingState.initialConnectionId,
		flowContext.flowRecord.flowKey.l4Protocol);
	if (!quicParsed) {
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	return parseQUIC(
		flowContext.flowRecord,
		quicParser,
		flowContext.packet.source_pkt,
		*pluginData);
}

void QUICPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<QUICData*>(pluginContext));
}

PluginDataMemoryLayout QUICPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(QUICData),
		.alignment = alignof(QUICData),
	};
}

static const PluginRegistrar<
	QUICPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	quicRegistrar(quicPluginManifest);

} // namespace ipxp
