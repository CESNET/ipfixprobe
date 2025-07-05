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

#include "ovpn.hpp"

#include <cstdint>
#include <cstring>
#include <iostream>

#include <endian.h>
#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

struct __attribute__((packed)) rtp_header {
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t csrc_count : 4;
	uint16_t extension : 1;
	uint16_t padding : 1;
	uint16_t version : 2;
	// next byte
	uint16_t payload_type : 7;
	uint16_t marker : 1;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version : 2;
	uint16_t padding : 1;
	uint16_t extension : 1;
	uint16_t csrc_count : 4;
	// next byte
	uint16_t marker : 1;
	uint16_t payload_type : 7;

#else // if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
#error "Please fix <endian.h>"
#endif // if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t sequence_number;
	uint32_t timestamp;
	uint32_t ssrc;
};

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

OVPNPlugin::OVPNPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

OVPNPlugin::~OVPNPlugin()
{
	close();
}

void OVPNPlugin::init(const char* params)
{
	(void) params;
}

void OVPNPlugin::close() {}

ProcessPlugin* OVPNPlugin::copy()
{
	return new OVPNPlugin(*this);
}

void OVPNPlugin::update_record(RecordExtOVPN* vpn_data, const Packet& pkt)
{
	uint8_t opcode = 0;
	uint8_t opcodeindex = 0;
	switch (static_cast<e_ip_proto_nbr>(pkt.ip_proto)) {
	case udp:
		if (pkt.payload_len == 0) {
			return;
		}
		opcodeindex = c_udp_opcode_index;
		opcode = (pkt.payload[opcodeindex] >> 3);
		break;
	case tcp:
		if (pkt.payload_len < c_tcp_opcode_index) {
			return;
		}
		opcodeindex = c_tcp_opcode_index;
		opcode = (pkt.payload[opcodeindex] >> 3);
		break;
	}

	switch (opcode) {
	// p_control_hard_reset_client
	case p_control_hard_reset_client_v1:
	case p_control_hard_reset_client_v2:
	case p_control_hard_reset_client_v3:
		vpn_data->status = status_reset_client; // client to server
		vpn_data->invalid_pkt_cnt = -1;
		vpn_data->client_ip = pkt.src_ip;
		break;

		// p_control_hard_reset_server
	case p_control_hard_reset_server_v1:
	case p_control_hard_reset_server_v2:
		if (vpn_data->status == status_reset_client
			&& compare_ip(vpn_data->client_ip, pkt.dst_ip, pkt.ip_version)) { // server to client
			vpn_data->status = status_reset_server;
			vpn_data->invalid_pkt_cnt = -1;
		} else {
			vpn_data->invalid_pkt_cnt++;
			if (vpn_data->invalid_pkt_cnt == invalid_pckt_treshold) {
				vpn_data->status = status_null;
			}
		}
		break;

		// p_control_soft_reset
	case p_control_soft_reset_v1:
		break;

		// p_control
	case p_control_v1:
		if (vpn_data->status == status_ack
			&& compare_ip(vpn_data->client_ip, pkt.src_ip, pkt.ip_version)
			&& check_ssl_client_hello(pkt, opcodeindex)) { // client to server
			vpn_data->status = status_client_hello;
			vpn_data->invalid_pkt_cnt = -1;
		} else if (
			vpn_data->status == status_client_hello
			&& compare_ip(vpn_data->client_ip, pkt.dst_ip, pkt.ip_version)
			&& check_ssl_server_hello(pkt, opcodeindex)) { // server to client
			vpn_data->status = status_server_hello;
			vpn_data->invalid_pkt_cnt = -1;
		} else if (
			vpn_data->status == status_server_hello || vpn_data->status == status_control_ack) {
			vpn_data->status = status_control_ack;
			vpn_data->invalid_pkt_cnt = -1;
		} else {
			vpn_data->invalid_pkt_cnt++;
			if (vpn_data->invalid_pkt_cnt == invalid_pckt_treshold) {
				vpn_data->status = status_null;
			}
		}
		break;

		// p_ack
	case p_ack_v1:
		if (vpn_data->status == status_reset_server
			&& compare_ip(vpn_data->client_ip, pkt.src_ip, pkt.ip_version)) { // client to server
			vpn_data->status = status_ack;
			vpn_data->invalid_pkt_cnt = -1;
		} else if (
			vpn_data->status == status_server_hello || vpn_data->status == status_control_ack) {
			vpn_data->status = status_control_ack;
			vpn_data->invalid_pkt_cnt = -1;
		}
		break;

		// p_data
	case p_data_v1:
	case p_data_v2:
		if (vpn_data->status == status_control_ack || vpn_data->status == status_data) {
			vpn_data->status = status_data;
			vpn_data->invalid_pkt_cnt = -1;
		}

		if (pkt.payload_len_wire > c_min_data_packet_size && !check_valid_rtp_header(pkt)) {
			vpn_data->data_pkt_cnt++;
		}
		break;

		// no opcode
	default:
		break;
	}

	if (pkt.payload_len_wire > c_min_data_packet_size && !check_valid_rtp_header(pkt)) {
		vpn_data->large_pkt_cnt++;
	}

	// packets that did not make a valid transition
	if (vpn_data->invalid_pkt_cnt >= invalid_pckt_treshold) {
		vpn_data->status = status_null;
		vpn_data->invalid_pkt_cnt = -1;
	}
	vpn_data->invalid_pkt_cnt++;
	return;
}

ProcessPlugin::FlowAction OVPNPlugin::post_create(Flow& rec, const Packet& pkt)
{
	RecordExtOVPN* vpn_data = new RecordExtOVPN(m_pluginID);
	rec.add_extension(vpn_data);

	update_record(vpn_data, pkt);
	return ProcessPlugin::FlowAction::GET_ALL_DATA;
}

ProcessPlugin::FlowAction OVPNPlugin::pre_update(Flow& rec, Packet& pkt)
{
	RecordExtOVPN* vpn_data = (RecordExtOVPN*) rec.get_extension(m_pluginID);
	update_record(vpn_data, pkt);
	if (rec.src_packets + rec.dst_packets <= min_pckt_export_treshold) {
		return ProcessPlugin::FlowAction::GET_ALL_DATA;
	}

	return vpn_data->status == status_null ?
		ProcessPlugin::FlowAction::GET_NO_DATA :
		ProcessPlugin::FlowAction::GET_ALL_DATA;
}

void OVPNPlugin::pre_export(Flow& rec)
{
	RecordExtOVPN* vpn_data = (RecordExtOVPN*) rec.get_extension(m_pluginID);

	// do not export ovpn for short flows, usually port scans
	uint32_t packets = rec.src_packets + rec.dst_packets;
	if (packets <= min_pckt_export_treshold) {
		rec.remove_extension(m_pluginID);
		return;
	}
	if ((rec.src_packets + rec.dst_packets) > min_pckt_treshold
		&& vpn_data->status == status_data) {
		vpn_data->possible_vpn = 100;
	} else if (
		vpn_data->large_pkt_cnt > min_pckt_treshold
		&& ((double) vpn_data->data_pkt_cnt / (double) vpn_data->large_pkt_cnt)
			>= data_pckt_treshold) {
		vpn_data->possible_vpn
			= (uint8_t) ((vpn_data->data_pkt_cnt / (double) vpn_data->large_pkt_cnt) * 80);
	}
	return;
}

bool OVPNPlugin::compare_ip(ipaddr_t ip_1, ipaddr_t ip_2, uint8_t ip_version)
{
	if (ip_version == IP::v4 && !memcmp(&ip_1, &ip_2, 4)) {
		return 1;
	} else if (ip_version == IP::v6 && !memcmp(&ip_1, &ip_2, 16)) {
		return 1;
	}
	return 0;
}

bool OVPNPlugin::check_ssl_client_hello(const Packet& pkt, uint8_t opcodeindex)
{
	if (pkt.payload_len > opcodeindex + 19 && pkt.payload[opcodeindex + 14] == 0x16
		&& pkt.payload[opcodeindex + 19] == 0x01) {
		return 1;
	} else if (
		pkt.payload_len > opcodeindex + 47 && pkt.payload[opcodeindex + 42] == 0x16
		&& pkt.payload[opcodeindex + 47] == 0x01) {
		return 1;
	}
	return 0;
}

bool OVPNPlugin::check_ssl_server_hello(const Packet& pkt, uint8_t opcodeindex)
{
	if (pkt.payload_len > opcodeindex + 31 && pkt.payload[opcodeindex + 26] == 0x16
		&& pkt.payload[opcodeindex + 31] == 0x02) {
		return 1;
	} else if (
		pkt.payload_len > opcodeindex + 59 && pkt.payload[opcodeindex + 54] == 0x16
		&& pkt.payload[opcodeindex + 59] == 0x02) {
		return 1;
	}
	return 0;
}

bool OVPNPlugin::check_valid_rtp_header(const Packet& pkt)
{
	if (pkt.ip_proto != IPPROTO_UDP)
		return false;

	if (pkt.payload_len < rtp_header_minimum_size)
		return false;

	struct rtp_header* rtp_header = (struct rtp_header*) pkt.payload;

	if (rtp_header->version != 2)
		return false;

	if (rtp_header->payload_type >= 72 && rtp_header->payload_type <= 95)
		return false;

	return true;
}

static const PluginRegistrar<OVPNPlugin, ProcessPluginFactory> ovpnRegistrar(ovpnPluginManifest);

} // namespace ipxp
