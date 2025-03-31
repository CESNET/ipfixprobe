/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * @author Pavel Siska <siska@cesnet.cz>
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "quic.hpp"

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

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

QUICPlugin::QUICPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

QUICPlugin::~QUICPlugin()
{
	close();
}

void QUICPlugin::init(const char* params)
{
	(void) params;
}

void QUICPlugin::close() {}

ProcessPlugin* QUICPlugin::copy()
{
	return new QUICPlugin(*this);
}

void QUICPlugin::set_cid_if_unset(
	bool& set_flag,
	uint8_t& src_id_length,
	char* src_id,
	uint8_t& dst_id_length,
	char* dst_id)
{
	if (!set_flag) {
		dst_id_length = src_id_length;
		memcpy(dst_id, src_id, src_id_length);
		set_flag = true;
	}
}

void QUICPlugin::set_stored_cid_fields(RecordExtQUIC* quic_data, bool new_quic_flow)
{
	if (!new_quic_flow & (quic_data->server_port != 0) & (quic_data->dir_dport != 0)) {
		if (quic_data->dir_dport == quic_data->server_port) {
			// to server
			// Check for CH to make sure it is a server chosen CID
			if (quic_data->client_hello_seen & quic_data->packet_from_server_seen) {
				set_cid_if_unset(
					quic_data->scid_set,
					quic_data->dir_dcid_length,
					quic_data->dir_dcid,
					quic_data->scid_length,
					quic_data->scid);
			}
			set_cid_if_unset(
				quic_data->occid_set,
				quic_data->dir_scid_length,
				quic_data->dir_scid,
				quic_data->occid_length,
				quic_data->occid);
		} else {
			// from server
			set_cid_if_unset(
				quic_data->scid_set,
				quic_data->dir_scid_length,
				quic_data->dir_scid,
				quic_data->scid_length,
				quic_data->scid);
			set_cid_if_unset(
				quic_data->occid_set,
				quic_data->dir_dcid_length,
				quic_data->dir_dcid,
				quic_data->occid_length,
				quic_data->occid);
		}
		quic_data->dir_dport = 0;

		if (quic_data->dir_dport2 != 0) {
			if (quic_data->dir_dport2 == quic_data->server_port) {
				// to server
				// Check for CH to make sure it is a server chosen CID
				if (quic_data->client_hello_seen & quic_data->packet_from_server_seen) {
					set_cid_if_unset(
						quic_data->scid_set,
						quic_data->dir_dcid_length2,
						quic_data->dir_dcid2,
						quic_data->scid_length,
						quic_data->scid);
				}
				set_cid_if_unset(
					quic_data->occid_set,
					quic_data->dir_scid_length2,
					quic_data->dir_scid2,
					quic_data->occid_length,
					quic_data->occid);
			} else {
				// from server
				set_cid_if_unset(
					quic_data->scid_set,
					quic_data->dir_scid_length2,
					quic_data->dir_scid2,
					quic_data->scid_length,
					quic_data->scid);
				set_cid_if_unset(
					quic_data->occid_set,
					quic_data->dir_dcid_length2,
					quic_data->dir_dcid2,
					quic_data->occid_length,
					quic_data->occid);
			}
			quic_data->dir_dport2 = 0;
		}
	}
}

void QUICPlugin::set_cid_fields(
	RecordExtQUIC* quic_data,
	Flow& rec,
	QUICParser* process_quic,
	int toServer,
	bool new_quic_flow,
	const Packet& pkt)
{
	uint8_t packets = get_packets_from_server(process_quic->quic_get_server_port(), rec);

	switch (toServer) {
	case 1:
		set_stored_cid_fields(quic_data, new_quic_flow);

		if ((!quic_data->scid_set) && (quic_data->packet_from_server_seen)
			&& (packets - 1 != quic_data->cnt_retry_packets)) {
			process_quic->quic_get_dcid(quic_data->scid);
			process_quic->quic_get_dcid_len(quic_data->scid_length);
			quic_data->scid_set = true;
		}

		if (!quic_data->occid_set) {
			process_quic->quic_get_scid(quic_data->occid);
			process_quic->quic_get_scid_len(quic_data->occid_length);
			quic_data->occid_set = true;
		}
		break;
	case 0:
		set_stored_cid_fields(quic_data, new_quic_flow);

		if (!quic_data->occid_set) {
			process_quic->quic_get_dcid(quic_data->occid);
			process_quic->quic_get_dcid_len(quic_data->occid_length);
			quic_data->occid_set = true;
		}

		if ((!quic_data->scid_set) & quic_data->packet_from_server_seen) {
			process_quic->quic_get_scid(quic_data->scid);
			process_quic->quic_get_scid_len(quic_data->scid_length);
			quic_data->scid_set = true;
		}

		break;
	case -1:
	default:
		// no direction information, store for future use
		// We store only information from the first packet per direction
		if ((quic_data->dir_dport != 0) && (quic_data->dir_dport2 == 0)
			&& (quic_data->dir_dport != pkt.dst_port)) {
			// conditions first is set, second is unset, other direction than first.
			// Store in secondary dataset
			process_quic->quic_get_scid(quic_data->dir_scid2);
			process_quic->quic_get_scid_len(quic_data->dir_scid_length2);
			process_quic->quic_get_dcid(quic_data->dir_dcid2);
			process_quic->quic_get_dcid_len(quic_data->dir_dcid_length2);
			quic_data->dir_dport2 = pkt.dst_port;
		}

		if (quic_data->dir_dport == 0) {
			process_quic->quic_get_scid(quic_data->dir_scid);
			process_quic->quic_get_scid_len(quic_data->dir_scid_length);
			process_quic->quic_get_dcid(quic_data->dir_dcid);
			process_quic->quic_get_dcid_len(quic_data->dir_dcid_length);
			quic_data->dir_dport = pkt.dst_port;
		}
		break;
	}
}

int QUICPlugin::get_direction_to_server_and_set_port(
	QUICParser* process_quic,
	RecordExtQUIC* quic_data,
	uint16_t parsed_port,
	const Packet& pkt,
	bool new_quic_flow)
{
	int toServer = get_direction_to_server(parsed_port, quic_data, pkt, new_quic_flow);
	if ((toServer != -1) && (quic_data->server_port == 0)) {
		quic_data->server_port = process_quic->quic_get_server_port();
	}
	if (toServer == 0) {
		quic_data->packet_from_server_seen = true;
	}
	return toServer;
}

int QUICPlugin::get_direction_to_server(
	uint16_t parsed_port,
	RecordExtQUIC* quic_data,
	const Packet& pkt,
	bool new_quic_flow)
{
	if (parsed_port != 0) {
		return pkt.dst_port == parsed_port;
	} else if ((!new_quic_flow) & (quic_data->server_port != 0)) {
		return pkt.dst_port == quic_data->server_port;
	}
	return -1;
}

uint8_t QUICPlugin::get_packets_from_server(uint16_t server_port, Flow& rec)
{
	uint8_t packets = 0;
	if (server_port == rec.src_port) {
		packets = rec.src_packets;
	} else {
		packets = rec.dst_packets;
	}
	return packets;
}

void QUICPlugin::set_client_hello_fields(
	QUICParser* process_quic,
	Flow& rec,
	RecordExtQUIC* quic_data,
	const Packet& pkt,
	bool new_quic_flow)
{
	(void) rec;
	(void) pkt;

	process_quic->quic_get_token_length(quic_data->quic_token_length);
	char dcid[MAX_CID_LEN] = {0};
	uint8_t dcid_len = 0;
	// since this is a client hello the dcid must be set
	process_quic->quic_get_dcid(dcid);
	process_quic->quic_get_dcid_len(dcid_len);

	if ((quic_data->quic_token_length
		 != QUICParser::QUIC_CONSTANTS::QUIC_UNUSED_VARIABLE_LENGTH_INT)
		&& (quic_data->quic_token_length > 0)
		&& ((quic_data->retry_scid_length == dcid_len)
			|| ((!new_quic_flow) && (quic_data->retry_scid_length == dcid_len)))
		&& ((strncmp(quic_data->retry_scid, dcid, std::min(quic_data->retry_scid_length, dcid_len))
			 == 0)
			|| ((!new_quic_flow)
				&& (strncmp(
					   quic_data->retry_scid,
					   dcid,
					   std::min(quic_data->retry_scid_length, dcid_len)))
					== 0))) {
		// CH after Retry case: We already have all information from the previous CH.

	} else {
		// MULTIPLEXING detection
		char oscid[MAX_CID_LEN] = {0};
		uint8_t oscid_len = 0;
		process_quic->quic_get_dcid(oscid);
		process_quic->quic_get_dcid_len(oscid_len);

		char sni[BUFF_SIZE] = {0};
		process_quic->quic_get_sni(sni);

		if ((new_quic_flow) || (!quic_data->client_hello_seen)
			|| ((quic_data->client_hello_seen)
				&& ((strncmp(oscid, quic_data->oscid, oscid_len) == 0) ||
					// Case that the first response message from server is received and the client
					// now uses that SCID as DCID.
					(quic_data->packet_from_server_seen && oscid_len == (quic_data->scid_length)
					 && (strncmp(oscid, quic_data->scid, oscid_len) == 0)))
				&& (strncmp(quic_data->sni, sni, BUFF_SIZE) == 0))) {
			// Repeated Initial or new Initial/QUIC flow
			quic_data->server_port = process_quic->quic_get_server_port();

			process_quic->quic_get_sni(quic_data->sni);
			process_quic->quic_get_user_agent(quic_data->user_agent);

			if (!quic_data->oscid_set) {
				process_quic->quic_get_dcid(quic_data->oscid);
				process_quic->quic_get_dcid_len(quic_data->oscid_length);
				quic_data->oscid_set = true;
			}

			if (!quic_data->occid_set) {
				process_quic->quic_get_scid(quic_data->occid);
				process_quic->quic_get_scid_len(quic_data->occid_length);
				quic_data->occid_set = true;
			}

			// Set client version to extract difference in compatible version negotiation: RFC9368
			if (!quic_data->client_version_set) {
				process_quic->quic_get_version(quic_data->quic_client_version);
				quic_data->client_version_set = true;
			}
		} else {
			if (quic_data->quic_multiplexed < 0xFF) {
				quic_data->quic_multiplexed += 1;
			}
		}
	}
}

void QUICPlugin::set_packet_type(RecordExtQUIC* quic_data, Flow& rec, uint8_t packets)
{
	uint32_t pos = rec.src_packets + rec.dst_packets - 1;
	if (pos < QUIC_MAX_ELEMCOUNT) {
		quic_data->pkt_types[pos] = packets;
		quic_data->last_pkt_type = pos;
	}
}

int QUICPlugin::process_quic(
	RecordExtQUIC* quic_data,
	Flow& rec,
	const Packet& pkt,
	bool new_quic_flow)
{
	QUICParser process_quic;

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

int QUICPlugin::pre_create(Packet& pkt)
{
	(void) pkt;
	return 0;
}

int QUICPlugin::post_create(Flow& rec, const Packet& pkt)
{
	return add_quic(rec, pkt);
}

int QUICPlugin::pre_update(Flow& rec, Packet& pkt)
{
	(void) rec;
	(void) pkt;
	return 0;
}

int QUICPlugin::post_update(Flow& rec, const Packet& pkt)
{
	return add_quic(rec, pkt);
}

int QUICPlugin::add_quic(Flow& rec, const Packet& pkt)
{
	RecordExtQUIC* q_ptr = (RecordExtQUIC*) rec.get_extension(m_pluginID);
	bool new_qptr = false;
	if (q_ptr == nullptr) {
		new_qptr = true;
		q_ptr = new RecordExtQUIC(m_pluginID);
	}

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

void QUICPlugin::finish(bool print_stats)
{
	if (print_stats) {
		std::cout << "QUIC plugin stats:" << std::endl;
		std::cout << "   Parsed SNI: " << parsed_initial << std::endl;
	}
}

static const PluginRegistrar<QUICPlugin, ProcessPluginFactory> quicRegistrar(quicPluginManifest);

} // namespace ipxp
