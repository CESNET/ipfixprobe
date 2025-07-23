/**
 * @file
 * @brief Switch records reader using unix domain sockets
 * @author Lokesh dhoundiyal <lokesh.dhoundiyal@alliedtelesis.co.nz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <ipfixprobe/inputPlugin.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/utils.hpp>


namespace ipxp {

#define SWITCH_RECORD_VERSION_V1 1

class SockOptParser : public OptionsParser {
	public:
	std::string m_sock;

	SockOptParser()
	: OptionsParser(
			"sock",
			"Input plugin for reading records from a unix domain socket")
			, m_sock("")
	{
		register_option(
		"s",
		"sock",
		"PATH",
		"Unix domain socket path",
		[this](const char* arg) {
			m_sock = arg;
			return true;
		},
		OptionFlags::RequiredArgument);
	}
};

class SockReader : public InputPlugin {
	public:
	SockReader(const std::string& params);
	~SockReader();
	void init(const char* params);
	void close();
	OptionsParser* get_parser() const { return new SockOptParser(); }
	std::string get_name() const { return "sock"; }
	InputPlugin::Result get(PacketBlock& packets);

	private:
	int sock;
	void open_sock(const std::string& m_sock);
	void set_packet(Packet* pkt, struct SwitchRecordData* recordData);
};

struct __attribute__((packed)) SwitchRecordData {
	struct timeval start_time;
	struct timeval end_time;
	uint8_t end_reason;
	uint8_t unused;

	uint32_t pkt_cnt;
	uint32_t drop_cnt;
	uint64_t byte_cnt;
	uint32_t src_if;

	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t eth_type;
	uint32_t vlan_id;

	uint8_t ip_version;
	uint8_t ip_proto;
	uint8_t tos;
	uint8_t ip_ttl;
	uint8_t ip_flags;
	uint16_t ip_length; /* Length of IP header + its payload */
	uint16_t ip_payload_len; /* Length of IP payload */

	uint16_t src_port;
	uint16_t dst_port;
	struct in_addr src_ip;
	struct in_addr dst_ip;
	struct in6_addr src_ip6;
	struct in6_addr dst_ip6;

	uint8_t tcp_control_bits;
	uint16_t tcp_window;
	uint32_t tcp_seq;
	uint32_t tcp_ack;

	/**
	 * \brief Constructor.
	 */
	SwitchRecordData()
		: start_time({0, 0})
		, end_time({0, 0})
		, end_reason(0)
		, pkt_cnt(0)
		, drop_cnt(0)
		, byte_cnt(0)
		, src_if(0)
		, dst_mac()
		, src_mac()
		, eth_type(0)
		, vlan_id(0)
		, ip_version(0)
		, ip_proto(0)
		, tos(0)
		, ip_ttl(0)
		, ip_flags(0)
		, ip_length(0)
		, ip_payload_len(0)
		, src_port(0)
		, dst_port(0)
		, src_ip({0})
		, dst_ip({0})
		, src_ip6({0})
		, dst_ip6({0})
		, tcp_control_bits(0)
		, tcp_window(0)
		, tcp_seq(0)
		, tcp_ack(0)
	{
	}
};

	struct __attribute__((packed)) SwitchRecordHdr {
		uint8_t version;
		uint8_t unused;
		uint16_t num_records;
	};
} // namespace ipxp

