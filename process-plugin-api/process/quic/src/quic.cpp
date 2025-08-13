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

#include "burstStats.hpp"

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

const inline std::vector<FieldPair<BurstStatsFields>> fields = {
	{BurstStatsFields::SBI_BRST_PACKETS, "SBI_BRST_PACKETS"},
};


static FieldSchema createQUICSchema()
{
	FieldSchema schema("quic");

	schema.addVectorField<uint32_t>(
		"SBI_BRST_PACKETS",
		FieldDirection::Forward,
		[](const void* thisPtr) -> std::span<const uint32_t> {
			return reinterpret_cast<const BurstStatsExport*>(thisPtr)
				->getPackets(Direction::Forward);
		});

	schema.addBiflowPair("SBI_BRST_TIME_START", "DBI_BRST_TIME_START");
	schema.addBiflowPair("SBI_BRST_TIME_STOP", "DBI_BRST_TIME_STOP");

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
	if (!serverId.empty() && m_exportData.serverConnectionId.empty()) {
		m_exportData.serverConnectionId = serverId;
	} 
	if (!currentIds[quicDirection].empty() && 
		m_exportData.serverConnectionId.empty()) {
		m_exportData.serverConnectionId = currentIds[quicDirection];
	}

	ConnectionId originalClientId = m_temporalCIDStorage.getClientCID(quicDirection);
	if (!originalClientId.empty() && m_exportData.clientConnectionId.empty()) {
		m_exportData.clientConnectionId = originalClientId;
	}
	if (!currentIds[!quicDirection].empty() && 
			m_exportData.clientConnectionId.empty()) {
		m_exportData.clientConnectionId = currentIds[!quicDirection];
	}
}

constexpr
void QUICPlugin::saveConnectionIdsToTemporalBuffer(
	const Direction direction,
	std::span<const uint8_t> sourceConnectionId,
	std::span<const uint8_t> destinationConnectionId
) noexcept
{
	
}


constexpr
void QUICPlugin::processInitial(
	const Direction flowDirection,
	const HeaderView& headerView,
	const InitialHeaderView& initialHeaderView,
	std::optional<QUICDirection> quicDirection) noexcept
{
	m_initialConnectionId = initialHeaderView.destinationConnectionId;
	if (!quicDirection.has_value()) {
		// Server is still not revealed, so we store those values to emplace them
		// when directions are known
		m_temporalCIDStorage.storeConnectionIds(
			flowDirection, 
			headerView.sourceConnectionId, 
			headerView.destinationConnectionId);
		return;
	}

	tryToSetOCCIDandSCID(...);

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
		multiplexedCount = std::min<uint16_t>(
			multiplexedCount + 1, std::numeric_limits<uint8_t>::max());
		return;
	}

	m_exportData.userAgent = initialHeaderView.userAgent;
	if (m_exportData.serverCID.empty()) {
		m_exportData.serverCID = destinationConnectionId;
	}
	if (m_exportData.clientCID.empty()) {
		m_exportData.clientCID = sourceConnectionId;
	}
	if (m_exportData.quicVersion == 0 ) {
		m_exportData.quicVersion = headerView.version;
	}

	if (m_exportData.tlsExtensionTypes.empty()) {
		std::ranges::copy(initialHeaderView |
			std::views::transform([](const TLSExtension& extension) {
				return extension.type;
			}) |
			std::views::take(m_exportData.tlsExtensionTypes.capacity()),
			std::back_inserter(m_exportData.tlsExtensionTypes));
	}

	if (m_exportData.tlsExtensionLengths.empty()) {
		std::ranges::copy(initialHeaderView |
			std::views::transform([](const TLSExtension& extension) {
				return extension.length;
			}) |
			std::views::take(m_exportData.tlsExtensionLengths.capacity()),
			std::back_inserter(m_exportData.tlsExtensionLengths));
	}

	if (m_exportData.extensionsPayload.empty()) {
		std::ranges::copy(initialHeaderView.extensionsPayload |
			std::views::take(QUICExport::MAX_BUFFER_SIZE),
			std::back_inserter(m_exportData.extensionsPayload));
	}
	


}

constexpr
void QUICPlugin::parseRetry() noexcept
{
	m_retryPacketCount++;
	/*
	* A client MUST accept and process at most one Retry packet for each connection
	* attempt. After the client has received and processed an Initial or Retry packet from
	* the server, it MUST discard any subsequent Retry packets that it receives.
	*/
	if (m_retryPacketCount == 1) {
		// Additionally set token len
		m_exportData.retryCID = sourceConnectionId;
		m_initialCID = destinationConnectionId;
		m_exportData.tokenLength = 16; // ?????????
	}

	if (m_exportData.clientCID.empty()) {
		m_exportData.clientCID = destinationConnectionId;
	}
}


int QUICPlugin::process_quic(
	RecordExtQUIC* quic_data,
	Flow& rec,
	const Packet& pkt,
	bool new_quic_flow)
{
	QUICParser quicParser;

	if (!quicParser.parse(payload, initialDestConnectionId)) {
		/// ??????????????????????
		m_exportData.packets.push_back(packetTypeCumulativeWithQUICBitSet);
		return QUIC_NOT_DETECTED;
	}

	if (quicParser.headerView.has_value() &&
		quicParser.packetTypesCumulative.bits.zeroRTT) {
		m_exportData.version = quicParser.headerView->versionId;
	}

	if (!m_exportData.packetTypes.full()) {
		m_exportData.packetTypes.push_back(
			static_cast<uint8_t>(quicParser.packetTypesCumulative.raw));
	}

	// TODO get direction ?

	if (version == QUICVersionId::version_negotiation) {
		set_cid_fields(quic_data, rec, &process_quic, toServer, new_quic_flow, pkt);
		return FlowAction::Flush;
	}

	if (quicParser.packetTypesCumulative.bits.zeroRTT) {
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

	switch (quicParser.packetType) {
	case QUICParser::PACKET_TYPE::INITIAL: {
		processInitial(...);
		break;
	}
	case QUICParser::PACKET_TYPE::HANDSHAKE:{ 
		if (!quicDirection.has_value()) {
			m_temporalCIDStorage.storeConnectionIds(
				flowDirection, 
				headerView.sourceConnectionId, 
				headerView.destinationConnectionId);
			break;
		}
		tryToSetOCCIDandSCID(...);
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

	return QUIC_DETECTED;


	// Test for QUIC LH packet in UDP payload
	if (process_quic.quic_check_quic_long_header_packet(
			pkt,
			quic_data->initial_dcid,
			quic_data->initial_dcid_length)) {
		uint32_t version;
		process_quic.quic_get_version(version);

		// Get kinds of packet included in datagram
		uint8_t packets = 0;
		process_quic.quic_get_packets(packets);

		// Store all QUIC packet types contained in each packet
		set_packet_type(quic_data, rec, packets);

		// A 0-RTT carries the same QUIC version as the Client Initial Hello.
		// 0-RTT and compatible version negotiation is not defined.
		// We ignore those cases because it might be defined in the future
		if ((packets & QUICParser::PACKET_TYPE_FLAG::F_ZERO_RTT) == 0) {
			quic_data->quic_version = version;
		}

		// Simple version, more advanced information is available after Initial parsing
		int toServer = get_direction_to_server_and_set_port(
			&process_quic,
			quic_data,
			process_quic.quic_get_server_port(),
			pkt,
			new_quic_flow);

		if (packets & QUICParser::PACKET_TYPE_FLAG::F_ZERO_RTT) {
			uint8_t zero_rtt_pkts = 0;
			process_quic.quic_get_zero_rtt(zero_rtt_pkts);

			if ((uint16_t) zero_rtt_pkts + (uint16_t) quic_data->quic_zero_rtt > 0xFF) {
				quic_data->quic_zero_rtt = 0xFF;
			} else {
				quic_data->quic_zero_rtt += zero_rtt_pkts;
			}
		}
		uint8_t parsed_initial = 0;

		if (version == QUICParser::QUIC_VERSION::version_negotiation) {
			set_cid_fields(quic_data, rec, &process_quic, toServer, new_quic_flow, pkt);
			return FLOW_FLUSH;
		}

		// export if parsed CH
		quic_data->parsed_ch |= process_quic.quic_get_parsed_ch();

		switch (process_quic.quic_get_packet_type()) {
		case QUICParser::PACKET_TYPE::INITIAL:
			process_quic.quic_get_parsed_initial(parsed_initial);
			// Store DCID from first observed Initial packet. This is used in the crypto operations.
			// Check length works because the first Initial must have a non-zero DCID.
			if (quic_data->initial_dcid_length == 0) {
				process_quic.quic_get_dcid_len(quic_data->initial_dcid_length);
				process_quic.quic_get_dcid(quic_data->initial_dcid);
				// Once established it can only be changed by a retry packet.
			}

			if (parsed_initial && (process_quic.quic_get_tls_hs_type() == 1)) {
				// Successful CH parsing
				set_stored_cid_fields(quic_data, new_quic_flow);
				set_client_hello_fields(&process_quic, rec, quic_data, pkt, new_quic_flow);
				quic_data->client_hello_seen = true;

				if (!quic_data->tls_ext_type_set) {
					process_quic.quic_get_tls_ext_type(quic_data->tls_ext_type);
					process_quic.quic_get_tls_ext_type_len(quic_data->tls_ext_type_len);
					quic_data->tls_ext_type_set = true;
				}

				if (!quic_data->tls_ext_len_set) {
					process_quic.quic_get_tls_extension_lengths(quic_data->tls_ext_len);
					process_quic.quic_get_tls_extension_lengths_len(quic_data->tls_ext_len_len);
					quic_data->tls_ext_len_set = true;
				}

				if (!quic_data->tls_ext_set) {
					process_quic.quic_get_tls_ext(quic_data->tls_ext);
					process_quic.quic_get_tls_ext_len(quic_data->tls_ext_length);
					quic_data->tls_ext_set = true;
				}
				break;
			}
			// Update accounting for information from CH, SH.
			toServer = get_direction_to_server_and_set_port(
				&process_quic,
				quic_data,
				process_quic.quic_get_server_port(),
				pkt,
				new_quic_flow);
			// fallthrough to set cids
			[[fallthrough]];
		case QUICParser::PACKET_TYPE::HANDSHAKE:
			// -1 sets stores intermediately.
			set_cid_fields(quic_data, rec, &process_quic, toServer, new_quic_flow, pkt);
			break;
		case QUICParser::PACKET_TYPE::RETRY:
			quic_data->cnt_retry_packets += 1;
			/*
			 * A client MUST accept and process at most one Retry packet for each connection
			 * attempt. After the client has received and processed an Initial or Retry packet from
			 * the server, it MUST discard any subsequent Retry packets that it receives.
			 */
			if (quic_data->cnt_retry_packets == 1) {
				// Additionally set token len
				process_quic.quic_get_scid(quic_data->retry_scid);
				process_quic.quic_get_scid_len(quic_data->retry_scid_length);
				// Update DCID for decryption
				process_quic.quic_get_dcid_len(quic_data->initial_dcid_length);
				process_quic.quic_get_scid(quic_data->initial_dcid);

				process_quic.quic_get_token_length(quic_data->quic_token_length);
			}

			if (!quic_data->occid_set) {
				process_quic.quic_get_dcid(quic_data->occid);
				process_quic.quic_get_dcid_len(quic_data->occid_length);
				quic_data->occid_set = true;
			}

			break;
		case QUICParser::PACKET_TYPE::ZERO_RTT:
			// Connection IDs are identical to Client Initial CH. The DCID might be OSCID at first
			// and change to SCID later. We ignore the DCID.
			if (!quic_data->occid_set) {
				process_quic.quic_get_scid(quic_data->occid);
				process_quic.quic_get_scid_len(quic_data->occid_length);
				quic_data->occid_set = true;
			}
			break;
		}

		return QUIC_DETECTED;
	} else {
		// Even if no QUIC detected store packets, which will only include the QUIC bit.
		uint8_t packets = 0;
		process_quic.quic_get_packets(packets);
		set_packet_type(quic_data, rec, packets);
	}
	return QUIC_NOT_DETECTED;
} // QUICPlugin::process_quic

FlowAction QUICPlugin::parseQUIC(Flow& rec, const Packet& pkt) noexcept
{

	int ret = process_quic(q_ptr, rec, pkt, new_qptr);
	// Test if QUIC extension is not set
	if (new_qptr && ((ret == QUIC_DETECTED) || (ret == FLOW_FLUSH))) {
		rec.add_extension(q_ptr);
	}
	if (new_qptr && (ret == QUIC_NOT_DETECTED)) {
		// If still no record delete q_ptr
		delete q_ptr;
	}
	// Correct if QUIC has already been detected
	if (!new_qptr && (ret == QUIC_NOT_DETECTED)) {
		return QUIC_DETECTED;
	}
	return ret;
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
