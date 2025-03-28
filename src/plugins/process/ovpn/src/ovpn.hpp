/**
 * @file
 * @brief Plugin for parsing ovpn traffic.
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Martin Ctrnacty <ctrnama2@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/processPlugin.hpp>

namespace ipxp {

#define OVPN_UNIREC_TEMPLATE "OVPN_CONF_LEVEL"

UR_FIELDS(uint8 OVPN_CONF_LEVEL)

/**
 * \brief Flow record extension header for storing parsed VPNDETECTOR packets.
 */
struct RecordExtOVPN : RecordExt {
	uint8_t possible_vpn;
	uint32_t large_pkt_cnt;
	uint32_t data_pkt_cnt;
	int32_t invalid_pkt_cnt;
	uint32_t status;
	ipaddr_t client_ip;

	RecordExtOVPN(int pluginID)
		: RecordExt(pluginID)
	{
		possible_vpn = 0;
		large_pkt_cnt = 0;
		data_pkt_cnt = 0;
		invalid_pkt_cnt = 0;
		status = 0;
	}

#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_OVPN_CONF_LEVEL, possible_vpn);
	}

	const char* get_unirec_tmplt() const { return OVPN_UNIREC_TEMPLATE; }
#endif

	virtual int fill_ipfix(uint8_t* buffer, int size)
	{
		if (size < 1) {
			return -1;
		}
		buffer[0] = (uint8_t) possible_vpn;
		return 1;
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_tmplt[] = {IPFIX_OVPN_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfix_tmplt;
	}

	std::string get_text() const
	{
		std::ostringstream out;
		out << "ovpnconf=" << (uint16_t) possible_vpn;
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing VPNDETECTOR packets.
 */
class OVPNPlugin : public ProcessPlugin {
public:
	OVPNPlugin(const std::string& params, int pluginID);
	~OVPNPlugin();
	void init(const char* params);
	void close();
	OptionsParser* get_parser() const
	{
		return new OptionsParser("ovpn", "OpenVPN detector plugin");
	}
	std::string get_name() const { return "ovpn"; }
	RecordExt* get_ext() const { return new RecordExtOVPN(m_pluginID); }
	ProcessPlugin* copy();

	int post_create(Flow& rec, const Packet& pkt);
	int pre_update(Flow& rec, Packet& pkt);
	void update_record(RecordExtOVPN* vpn_data, const Packet& pkt);
	void pre_export(Flow& rec);

	typedef enum e_ip_proto_nbr { tcp = 6, udp = 17 } e_ip_proto_nbr;

	static const uint32_t c_min_data_packet_size = 500;
	static const uint32_t c_udp_opcode_index = 0;
	static const uint32_t c_tcp_opcode_index = 2;
	static const uint32_t min_pckt_treshold = 20;
	static const uint32_t min_pckt_export_treshold = 5;
	static constexpr float data_pckt_treshold = 0.6f;
	static const int32_t invalid_pckt_treshold = 4;
	static const uint32_t min_opcode = 1;
	static const uint32_t max_opcode = 10;
	static const uint32_t p_control_hard_reset_client_v1
		= 1; /* initial key from client, forget previous state */
	static const uint32_t p_control_hard_reset_server_v1
		= 2; /* initial key from server, forget previous state */
	static const uint32_t p_control_soft_reset_v1
		= 3; /* new key, graceful transition from old to new key */
	static const uint32_t p_control_v1 = 4; /* control channel packet (usually tls ciphertext) */
	static const uint32_t p_ack_v1 = 5; /* acknowledgement for packets received */
	static const uint32_t p_data_v1 = 6; /* data channel packet */
	static const uint32_t p_data_v2 = 9; /* data channel packet with peer-id */
	static const uint32_t p_control_hard_reset_client_v2
		= 7; /* initial key from client, forget previous state */
	static const uint32_t p_control_hard_reset_server_v2
		= 8; /* initial key from server, forget previous state */
	static const uint32_t p_control_hard_reset_client_v3
		= 10; /* initial key from client, forget previous state */
	static const uint32_t status_null = 0;
	static const uint32_t status_reset_client = 1;
	static const uint32_t status_reset_server = 2;
	static const uint32_t status_ack = 3;
	static const uint32_t status_client_hello = 4;
	static const uint32_t status_server_hello = 5;
	static const uint32_t status_control_ack = 6;
	static const uint32_t status_data = 7;
	static const uint32_t rtp_header_minimum_size = 12;

private:
	bool compare_ip(ipaddr_t ip_1, ipaddr_t ip_2, uint8_t ip_version);
	bool check_ssl_client_hello(const Packet& pkt, uint8_t opcodeindex);
	bool check_ssl_server_hello(const Packet& pkt, uint8_t opcodeindex);
	bool check_valid_rtp_header(const Packet& pkt);
};

} // namespace ipxp
