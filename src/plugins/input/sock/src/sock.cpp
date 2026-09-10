/**
 * @file
 * @brief Switch records reader from unix domain sockets.
 * This is useful plugin for devices with IPFIX support in silicon.
 * A switch record identified by the device can be sent to
 * this input plugin via a unix domain socket for processing
 * exporting to a collector.
 * @author Lokesh dhoundiyal <lokesh.dhoundiyal@alliedtelesis.co.nz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "sock.hpp"
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <ifaddrs.h>
#include <iostream>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>


namespace ipxp {

// Print debug message if debugging is allowed.
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
// Process code if debugging is allowed.
#define DEBUG_CODE(code) code


static const PluginManifest sockPluginManifest = {
	.name = "sock",
	.description = "sock input plugin for reading ipfix flow records from a unix domain socket.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			SockOptParser parser;
			parser.usage(std::cout);
		},
};

SockReader::SockReader(const std::string& params)
	: sock(-1)
{
	init(params.c_str());
}

SockReader::~SockReader()
{
	close();
}

void SockReader::init(const char* params)
{
	SockOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	if (parser.m_sock.empty()) {
		throw PluginError("specify socket path");
	}

	open_sock(parser.m_sock);
}

void SockReader::close()
{
	if (sock >= 0) {
		::close(sock);
		sock = -1;
	}
}

void SockReader::open_sock(const std::string& m_sock)
{
	int server_sock, len, rc;
	struct sockaddr_un server_sockaddr;

	server_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (server_sock == -1) {
		throw PluginError(
			std::string("could not create AF_UNIX socket: ") + strerror(errno));
	}

	server_sockaddr.sun_family = AF_UNIX;
	strcpy(server_sockaddr.sun_path, m_sock.c_str());
	len = sizeof(server_sockaddr);
	unlink(m_sock.c_str());
	rc = bind(server_sock, (struct sockaddr*)&server_sockaddr, len);
	if (rc == -1) {
		::close(server_sock);
		throw PluginError(
			std::string("bind failed: ") + strerror(errno));
	}
	sock = server_sock;
}

void SockReader::set_packet(Packet* pkt, struct SwitchRecordData* recordData)
{
	char dst_str[INET6_ADDRSTRLEN];
	char src_str[INET6_ADDRSTRLEN];

	DEBUG_CODE(char timestamp[32]; time_t time = recordData->start_time.tv_sec;
	  strftime(timestamp, sizeof(timestamp), "%FT%T", localtime(&time)););
	DEBUG_MSG("Time:\t\t\t%s.%06lu\n", timestamp, recordData->start_time.tv_usec);
	DEBUG_MSG("Source interface:\t%u\n", recordData->src_if);

	pkt->ts = recordData->start_time;
	pkt->end_ts = recordData->end_time;
	pkt->end_reason = recordData->end_reason;
	pkt->ip_version = recordData->ip_version;
	pkt->source_interface = recordData->src_if;
	pkt->src_port = 0;
	pkt->dst_port = 0;
	pkt->ip_proto = 0;
	pkt->ip_ttl = 0;
	pkt->ip_flags = 0;
	pkt->ip_payload_len = 0;
	pkt->tcp_flags = 0;
	pkt->tcp_window = 0;
	pkt->tcp_options = 0;
	pkt->tcp_mss = 0;
	memcpy(pkt->dst_mac, recordData->dst_mac, sizeof(recordData->dst_mac));
	memcpy(pkt->src_mac, recordData->src_mac, sizeof(recordData->src_mac));
	pkt->ethertype = recordData->eth_type;
	pkt->vlan_id = recordData->vlan_id;
	pkt->ip_tos = recordData->tos;

	DEBUG_CODE(
		char src_mac[18]; // ether_ntoa missing on some platforms
		char dst_mac[18];
		uint8_t *p = (uint8_t *) pkt->src_mac;
		snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
		p = (uint8_t *) pkt->dst_mac;
		snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
	);
	DEBUG_MSG("\tDest mac:\t%s\n", dst_mac);
	DEBUG_MSG("\tSrc mac:\t%s\n", src_mac);
	DEBUG_MSG("\tEthertype:\t%#06x\n", pkt->ethertype);
	DEBUG_MSG("\tVLAN:\t%u\n", pkt->vlan_id);

	if (pkt->ip_version == 4) {
		pkt->src_ip.v4 = recordData->src_ip.s_addr;
		pkt->dst_ip.v4 = recordData->dst_ip.s_addr;
		inet_ntop(AF_INET, &recordData->src_ip, src_str, 16);
		inet_ntop(AF_INET, &recordData->dst_ip, dst_str, 16);
		DEBUG_MSG("IPv4 header:\n");
	}
	else if (pkt->ip_version == 6) {
		memcpy(pkt->src_ip.v6, recordData->src_ip6.s6_addr, 16);
		memcpy(pkt->dst_ip.v6, recordData->dst_ip6.s6_addr, 16);
		inet_ntop(AF_INET6, &recordData->src_ip6, src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &recordData->dst_ip6, dst_str, INET6_ADDRSTRLEN);
		DEBUG_MSG("IPv6 header:\n");
	}

	pkt->ip_proto = recordData->ip_proto;
	pkt->ip_len = recordData->ip_length;
	pkt->ip_ttl = recordData->ip_ttl;
	pkt->ip_flags = recordData->ip_flags;
	pkt->ip_payload_len = recordData->ip_payload_len;

	DEBUG_MSG("\tHDR version:\t%u\n", pkt->ip_version);
	DEBUG_MSG("\tHDR length:\t%u\n", pkt->ip_payload_len);
	DEBUG_MSG("\tTotal length:\t%u\n", pkt->ip_len);
	DEBUG_MSG("\tTOS:\t\t%u\n", pkt->ip_tos);
	DEBUG_MSG("\tProtocol:\t%u\n", pkt->ip_proto);
	DEBUG_MSG("\tSrc addr:\t%s\n", src_str);
	DEBUG_MSG("\tDest addr:\t%s\n", dst_str);
	DEBUG_MSG("\tFlags:\t\t%#x\n", pkt->ip_flags);
	DEBUG_MSG("\tTTL:\t\t%u\n", pkt->ip_ttl);

	pkt->src_port = recordData->src_port;
	pkt->dst_port = recordData->dst_port;
	if (pkt->ip_proto == IPPROTO_TCP) {
		pkt->tcp_flags = recordData->tcp_control_bits;
		pkt->tcp_window = recordData->tcp_window;
		pkt->tcp_seq = recordData->tcp_seq;
		pkt->tcp_ack = recordData->tcp_ack;
		DEBUG_MSG("TCP header:\n");
		DEBUG_MSG("\tSrc port:\t%u\n", pkt->src_port);
		DEBUG_MSG("\tDest port:\t%u\n", pkt->dst_port);
		DEBUG_MSG("\tFlags:\t%u\n", pkt->tcp_flags);
		DEBUG_MSG("\tSEQ:\t\t%#x\n", pkt->tcp_seq);
		DEBUG_MSG("\tACK SEQ:\t%#x\n", pkt->tcp_ack);
		DEBUG_MSG("\tWindow:\t\t%u\n", pkt->tcp_window);
	}
	if (pkt->ip_proto == IPPROTO_UDP) {
		DEBUG_MSG("UDP header:\n");
		DEBUG_MSG("\tSrc port:\t%u\n", pkt->src_port);
		DEBUG_MSG("\tDest port:\t%u\n", pkt->dst_port);
	}

	pkt->pkt_cnt = recordData->pkt_cnt;
	pkt->byte_cnt = recordData->byte_cnt;
	DEBUG_MSG("Packet count %u byte count: %lu\n", pkt->pkt_cnt, pkt->byte_cnt);
}

InputPlugin::Result SockReader::get(PacketBlock& pblock)
{
	int bytes_rec = -1;
	struct sockaddr_un peer_sock;
	int len;
	Packet* pkt;
	struct SwitchRecordData* recordData;
	struct SwitchRecordHdr* recordHdr;
	uint8_t recordHdrBuffer[sizeof(struct SwitchRecordHdr)];
	int recordBuffer_size;
	uint8_t* recordBuffer = NULL;

	bytes_rec = recvfrom(sock, recordHdrBuffer, sizeof(struct SwitchRecordHdr), MSG_PEEK | MSG_DONTWAIT,
		(struct sockaddr*) &peer_sock, (socklen_t*) &len);
	if (bytes_rec == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return Result::TIMEOUT;
		} else {
			::close(sock);
			throw PluginError(std::string("recvfrom failed: ") + strerror(errno));
		}
	} else {
		recordHdr = (struct SwitchRecordHdr*) recordHdrBuffer;
		DEBUG_MSG("Switch record version: %u num_records %u bytes_rec %d\n",
			recordHdr->version, recordHdr->num_records, bytes_rec);

		  if (recordHdr->version == SWITCH_RECORD_VERSION_V1) {
			recordBuffer_size = sizeof(struct SwitchRecordHdr) +
				(sizeof(struct SwitchRecordData) * recordHdr->num_records);

			recordBuffer = (uint8_t*) malloc(recordBuffer_size);
			if (!recordBuffer) {
				::close(sock);
				throw PluginError("not enough memory");
			 } else {
				bytes_rec = recvfrom(sock, recordBuffer, recordBuffer_size, 0,
				(struct sockaddr*) &peer_sock, (socklen_t*) &len);
				if (bytes_rec == -1) {
				::close(sock);
				throw PluginError(std::string("recvfrom failed: ") + strerror(errno));
				} else {
				pblock.cnt = 0;
				DEBUG_MSG("bytes_rec :%d \n", bytes_rec);
				recordData = (struct SwitchRecordData*) (recordBuffer + sizeof(struct SwitchRecordHdr));
				for (int i = 0; i < recordHdr->num_records; i++, recordData++) {
					  pkt = &pblock.pkts[pblock.cnt];
					  if (recordData) {
						DEBUG_MSG("Record count: %d\n", i);
						set_packet(pkt, recordData);
						pblock.cnt++;
						pblock.bytes += pkt->ip_len;
						m_seen += recordData->pkt_cnt;
						m_parsed += recordData->pkt_cnt;
					}
				}
				}
			 }
		  }
	}
	free(recordBuffer);
	return pblock.cnt ? Result::PARSED : Result::NOT_PARSED;
}

static const PluginRegistrar<SockReader, InputPluginFactory> sockRegistrar(sockPluginManifest);
} // namespace ipxp
