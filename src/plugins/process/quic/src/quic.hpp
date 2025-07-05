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

#pragma once

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include "quic_parser.hpp"

#include <iomanip>
#include <sstream>

#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

#define QUIC_UNIREC_TEMPLATE                                                                       \
	"QUIC_SNI,QUIC_USER_AGENT,QUIC_VERSION,QUIC_CLIENT_VERSION,QUIC_TOKEN_LENGTH,QUIC_OCCID,QUIC_" \
	"OSCID,QUIC_SCID,QUIC_RETRY_SCID,QUIC_MULTIPLEXED,QUIC_ZERO_RTT,QUIC_SERVER_PORT,QUIC_"        \
	"PACKETS,QUIC_CH_PARSED,QUIC_TLS_EXT_TYPE,QUIC_TLS_EXT_LEN,QUIC_TLS_EXT"

UR_FIELDS(
	string QUIC_SNI,
	string QUIC_USER_AGENT,
	uint32 QUIC_VERSION,
	uint32 QUIC_CLIENT_VERSION,
	uint64 QUIC_TOKEN_LENGTH,
	bytes QUIC_OCCID,
	bytes QUIC_OSCID,
	bytes QUIC_SCID,
	bytes QUIC_RETRY_SCID,
	uint8 QUIC_MULTIPLEXED,
	uint8 QUIC_ZERO_RTT,
	uint16 QUIC_SERVER_PORT,
	uint8* QUIC_PACKETS,
	uint8 QUIC_CH_PARSED,
	uint16* QUIC_TLS_EXT_TYPE,
	uint16* QUIC_TLS_EXT_LEN,
	bytes QUIC_TLS_EXT)

/**
 * \brief Flow record extension header for storing parsed QUIC packets.
 */
#define QUIC_MAX_ELEMCOUNT 30
#define MAX_CID_LEN 20
#define QUIC_DETECTED 0
#define QUIC_NOT_DETECTED 2
#define QUIC_PKT_FIELD_ID 888
#define QUIC_TLS_EXT_TYPE_FIELD_ID 885
#define QUIC_TLS_EXT_LEN_FIELD_ID 884

struct RecordExtQUIC : public RecordExt {
	char sni[BUFF_SIZE] = {0};
	char user_agent[BUFF_SIZE] = {0};
	uint32_t quic_version;
	uint32_t quic_client_version;
	uint64_t quic_token_length;
	// We use a char as a buffer.
	uint8_t occid_length;
	uint8_t oscid_length;
	uint8_t scid_length;
	uint8_t initial_dcid_length;
	uint8_t dir_scid_length;
	uint8_t dir_dcid_length;
	uint8_t dir_scid_length2;
	uint8_t dir_dcid_length2;
	uint8_t retry_scid_length;
	char occid[MAX_CID_LEN] = {0};
	char oscid[MAX_CID_LEN] = {0};
	char scid[MAX_CID_LEN] = {0};
	char initial_dcid[MAX_CID_LEN] = {0};
	char retry_scid[MAX_CID_LEN] = {0};
	// Intermediate storage when direction is not clear
	char dir_scid[MAX_CID_LEN] = {0};
	char dir_dcid[MAX_CID_LEN] = {0};
	char dir_scid2[MAX_CID_LEN] = {0};
	char dir_dcid2[MAX_CID_LEN] = {0};
	uint16_t dir_dport;
	uint16_t dir_dport2;
	uint16_t server_port;
	uint8_t cnt_retry_packets;

	uint8_t quic_multiplexed;
	uint8_t quic_zero_rtt;
	uint8_t pkt_types[QUIC_MAX_ELEMCOUNT];

	uint16_t tls_ext_type[MAX_QUIC_TLS_EXT_LEN];
	uint16_t tls_ext_type_len;
	bool tls_ext_type_set;

	uint16_t tls_ext_len[MAX_QUIC_TLS_EXT_LEN];
	uint8_t tls_ext_len_len;
	bool tls_ext_len_set;

	char tls_ext[CURRENT_BUFFER_SIZE];
	uint16_t tls_ext_length;
	bool tls_ext_set;

	uint8_t last_pkt_type;

	uint8_t parsed_ch;

	// Flags to ease decisions
	bool occid_set;
	bool oscid_set;
	bool scid_set;

	bool client_version_set;
	bool client_hello_seen;
	bool packet_from_server_seen;

	RecordExtQUIC(int pluginID)
		: RecordExt(pluginID)
	{
		sni[0] = 0;
		user_agent[0] = 0;
		quic_version = 0;
		quic_client_version = 0;
		occid_length = 0;
		oscid_length = 0;
		scid_length = 0;
		retry_scid_length = 0;
		occid[0] = 0;
		oscid[0] = 0;
		scid[0] = 0;
		retry_scid[0] = 0;
		dir_dcid[0] = 0;
		dir_scid[0] = 0;
		dir_dcid_length = 0;
		dir_scid_length = 0;
		dir_dcid2[0] = 0;
		dir_scid2[0] = 0;
		dir_dcid_length2 = 0;
		dir_scid_length2 = 0;
		server_port = 0;
		dir_dport = 0;
		dir_dport2 = 0;
		quic_token_length = QUICParser::QUIC_CONSTANTS::QUIC_UNUSED_VARIABLE_LENGTH_INT;
		quic_multiplexed = 0;
		quic_zero_rtt = 0;
		memset(pkt_types, 0, sizeof(pkt_types));

		memset(tls_ext_type, 0, sizeof(tls_ext_type));
		tls_ext_type_len = 0;
		tls_ext_type_set = false;

		memset(tls_ext_len, 0, sizeof(tls_ext_len));
		tls_ext_len_len = 0;
		tls_ext_len_set = false;

		memset(tls_ext, 0, sizeof(tls_ext));
		tls_ext_length = 0;
		tls_ext_set = false;

		last_pkt_type = 0;
		initial_dcid[0] = 0;
		initial_dcid_length = 0;
		parsed_ch = 0;

		occid_set = false;
		oscid_set = false;
		scid_set = false;
		client_version_set = false;
		cnt_retry_packets = 0;

		client_hello_seen = false;
		packet_from_server_seen = false;
	}

#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		ur_set_string(tmplt, record, F_QUIC_SNI, sni);
		ur_set_string(tmplt, record, F_QUIC_USER_AGENT, user_agent);
		ur_set(tmplt, record, F_QUIC_VERSION, quic_version);
		ur_set(tmplt, record, F_QUIC_CLIENT_VERSION, quic_client_version);
		ur_set(tmplt, record, F_QUIC_TOKEN_LENGTH, quic_token_length);
		ur_set_var(tmplt, record, F_QUIC_OCCID, occid, occid_length);
		ur_set_var(tmplt, record, F_QUIC_OSCID, oscid, oscid_length);
		ur_set_var(tmplt, record, F_QUIC_SCID, scid, scid_length);
		ur_set_var(tmplt, record, F_QUIC_RETRY_SCID, retry_scid, retry_scid_length);
		ur_set(tmplt, record, F_QUIC_MULTIPLEXED, quic_multiplexed);
		ur_set(tmplt, record, F_QUIC_ZERO_RTT, quic_zero_rtt);
		ur_set(tmplt, record, F_QUIC_SERVER_PORT, server_port);
		ur_array_allocate(tmplt, record, F_QUIC_PACKETS, last_pkt_type + 1);
		for (int i = 0; i < last_pkt_type + 1; i++) {
			ur_array_set(tmplt, record, F_QUIC_PACKETS, i, pkt_types[i]);
		}
		ur_set(tmplt, record, F_QUIC_CH_PARSED, parsed_ch);
		ur_array_allocate(tmplt, record, F_QUIC_TLS_EXT_TYPE, tls_ext_type_len);
		for (int i = 0; i < tls_ext_type_len; i++) {
			ur_array_set(tmplt, record, F_QUIC_TLS_EXT_TYPE, i, tls_ext_type[i]);
		}
		ur_array_allocate(tmplt, record, F_QUIC_TLS_EXT_LEN, tls_ext_len_len);
		for (int i = 0; i < tls_ext_len_len; i++) {
			ur_array_set(tmplt, record, F_QUIC_TLS_EXT_LEN, i, tls_ext_len[i]);
		}
		ur_set_var(tmplt, record, F_QUIC_TLS_EXT, tls_ext, tls_ext_length);
	}

	const char* get_unirec_tmplt() const { return QUIC_UNIREC_TEMPLATE; }

#endif // ifdef WITH_NEMEA

	virtual int fill_ipfix(uint8_t* buffer, int size)
	{
		IpfixBasicList basiclist;
		basiclist.hdrEnterpriseNum = IpfixBasicList::CesnetPEM;
		uint16_t len_sni = strlen(sni);
		uint16_t len_user_agent = strlen(user_agent);
		uint16_t len_version = sizeof(quic_version);
		uint16_t len_client_version = sizeof(quic_client_version);
		uint16_t len_token_length = sizeof(quic_token_length);
		uint16_t len_multiplexed = sizeof(quic_multiplexed);
		uint16_t len_zero_rtt = sizeof(quic_zero_rtt);
		uint16_t pkt_types_len
			= sizeof(pkt_types[0]) * (last_pkt_type + 1) + basiclist.HeaderSize();
		uint16_t len_server_port = sizeof(server_port);
		uint16_t len_parsed_ch = sizeof(parsed_ch);

		uint16_t len_tls_ext_type
			= sizeof(tls_ext_type[0]) * (tls_ext_type_len) + basiclist.HeaderSize();
		uint16_t len_tls_len = sizeof(tls_ext_len[0]) * (tls_ext_len_len) + basiclist.HeaderSize();
		uint16_t len_tls_ext = tls_ext_length + 3;

		uint32_t pos = 0;

		if ((len_sni + 3) + (len_user_agent + 3) + len_version + len_client_version
				+ len_token_length + len_multiplexed + len_zero_rtt + (scid_length + 3)
				+ (occid_length + 3) + (oscid_length + 3) + (retry_scid_length + 3)
				+ len_server_port + pkt_types_len + len_parsed_ch + len_tls_ext_type + len_tls_len
				+ len_tls_ext + 3 * basiclist.HeaderSize()
			> size) {
			return -1;
		}

		pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) sni, len_sni);
		pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) user_agent, len_user_agent);
		*(uint32_t*) (buffer + pos) = htonl(quic_version);
		pos += len_version;
		*(uint32_t*) (buffer + pos) = htonl(quic_client_version);
		pos += len_client_version;
		*(uint64_t*) (buffer + pos) = htobe64(quic_token_length);
		pos += len_token_length;
		// original client connection ID
		pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) occid, occid_length);
		// original server connection id
		pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) oscid, oscid_length);
		// server connection id
		pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) scid, scid_length);
		// retry server connection id
		pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) retry_scid, retry_scid_length);

		*(uint8_t*) (buffer + pos) = quic_multiplexed;
		pos += 1;

		*(uint8_t*) (buffer + pos) = quic_zero_rtt;
		pos += 1;
		*(uint16_t*) (buffer + pos) = htons(server_port);
		pos += len_server_port;
		// Packet types
		pos += basiclist.FillBuffer(
			buffer + pos,
			pkt_types,
			(uint16_t) last_pkt_type + 1,
			(uint16_t) QUIC_PKT_FIELD_ID);

		*(uint8_t*) (buffer + pos) = parsed_ch;
		pos += 1;

		pos += basiclist.FillBuffer(
			buffer + pos,
			tls_ext_type,
			(uint16_t) tls_ext_type_len,
			(uint16_t) QUIC_TLS_EXT_TYPE_FIELD_ID);
		pos += basiclist.FillBuffer(
			buffer + pos,
			tls_ext_len,
			(uint16_t) tls_ext_len_len,
			(uint16_t) QUIC_TLS_EXT_LEN_FIELD_ID);
		pos += variable2ipfix_buffer(buffer + pos, (uint8_t*) tls_ext, tls_ext_length);

		return pos;
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_template[] = {IPFIX_QUIC_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfix_template;
	}

	std::string get_text() const
	{
		std::ostringstream out;

		out << "quicsni=\"" << sni << "\""
			<< "quicuseragent=\"" << user_agent << "\""
			<< "quicversion=\"" << quic_version << "\""
			<< "quicclientversion=\"" << quic_client_version << "\""
			<< "quicoccidlength=\"" << (int) occid_length << "\"";
		out << "quicoccid=\"";
		for (int i = 0; i < occid_length; i++) {
			out << std::hex << (occid[i] & 0xff);
		}
		out << "\""
			<< "quicoscidlength=\"" << std::dec << (int) oscid_length << "\"";
		out << "quicoscid=\"";
		for (int i = 0; i < oscid_length; i++) {
			out << std::hex << (oscid[i] & 0xff);
		}
		out << "\""
			<< "quicscidlength=\"" << std::dec << (int) scid_length << "\"";
		out << "quicscid=\"";
		for (int i = 0; i < scid_length; i++) {
			out << std::hex << (scid[i] & 0xff);
		}
		out << "\""
			<< "quicmultiplexed=\"" << std::dec << (int) quic_multiplexed << "\""
			<< "quiczerortt=\"" << (int) quic_zero_rtt << "\""
			<< "quicparsedch=\"" << (int) parsed_ch << "\"";
		out << "quictlsexttype=(";
		for (int i = 0; i < tls_ext_type_len; i++) {
			out << std::dec << (uint16_t) tls_ext_type[i];
			if (i != tls_ext_type_len - 1) {
				out << ",";
			}
		}
		out << ")quictlsextlen=(";
		for (int i = 0; i < tls_ext_len_len; i++) {
			out << std::dec << (uint16_t) tls_ext_len[i];
			if (i != tls_ext_len_len - 1) {
				out << ",";
			}
		}
		out << ")quictlsext=\"";
		for (int i = 0; i < tls_ext_length; i++) {
			out << std::hex << std::setw(2) << std::setfill('0') << (uint16_t) tls_ext[i];
		}
		out << "\"";

		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing QUIC packets.
 */
class QUICPlugin : public ProcessPlugin {
public:
	QUICPlugin(const std::string& params, int pluginID);
	~QUICPlugin();
	void init(const char* params);
	void close();
	RecordExt* get_ext() const { return new RecordExtQUIC(m_pluginID); }

	OptionsParser* get_parser() const { return new OptionsParser("quic", "Parse QUIC traffic"); }

	std::string get_name() const { return "quic"; }

	ProcessPlugin* copy();

	ProcessPlugin::FlowAction post_create(Flow& rec, const Packet& pkt);
	ProcessPlugin::FlowAction post_update(Flow& rec, const Packet& pkt);
	ProcessPlugin::FlowAction add_quic(Flow& rec, const Packet& pkt);
	void finish(bool print_stats);
	void set_packet_type(RecordExtQUIC* quic_data, Flow& rec, uint8_t packets);

private:
	ProcessPlugin::FlowAction process_quic(RecordExtQUIC*, Flow& rec, const Packet&, bool new_quic_flow);
	void set_stored_cid_fields(RecordExtQUIC* quic_data, bool new_quic_flow);
	void set_cid_fields(
		RecordExtQUIC* quic_data,
		Flow& rec,
		QUICParser* process_quic,
		int toServer,
		bool new_quic_flow,
		const Packet& pkt);
	int get_direction_to_server(
		uint16_t parsed_port,
		RecordExtQUIC* quic_data,
		const Packet& pkt,
		bool new_quic_flow);
	int get_direction_to_server_and_set_port(
		QUICParser* process_quic,
		RecordExtQUIC* quic_data,
		uint16_t parsed_port,
		const Packet& pkt,
		bool new_quic_flow);
	void set_client_hello_fields(
		QUICParser* process_quic,
		Flow& rec,
		RecordExtQUIC* quic_data,
		const Packet& pkt,
		bool new_quic_flow);
	void set_cid_if_unset(
		bool& set_flag,
		uint8_t& src_id_length,
		char* src_id,
		uint8_t& dst_id_length,
		char* dst_id);
	uint8_t get_packets_from_server(uint16_t server_port, Flow& rec);

	int parsed_initial;
	RecordExtQUIC* quic_ptr;
};

} // namespace ipxp
