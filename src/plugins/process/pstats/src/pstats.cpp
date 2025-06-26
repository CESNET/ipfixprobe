/**
 * @file
 * @brief Plugin for parsing pstats traffic.
 * @author Tomas Cejka <cejkat@cesnet.cz>
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pstats.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

static const PluginManifest pstatsPluginManifest = {
	.name = "pstats",
	.description = "Pstats process plugin for computing packet bursts stats.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			PSTATSOptParser parser;
			parser.usage(std::cout);
		},
};

// #define DEBUG_PSTATS

// Print debug message if debugging is allowed.
#ifdef DEBUG_PSTATS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

PSTATSPlugin::PSTATSPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
	, use_zeros(false)
	, skip_dup_pkts(false)
{
	init(params.c_str());
}

PSTATSPlugin::~PSTATSPlugin()
{
	close();
}

void PSTATSPlugin::init(const char* params)
{
	PSTATSOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	use_zeros = parser.m_include_zeroes;
	skip_dup_pkts = parser.m_skipdup;
}

void PSTATSPlugin::close() {}

ProcessPlugin* PSTATSPlugin::copy()
{
	return new PSTATSPlugin(*this);
}

inline bool seq_overflowed(uint32_t curr, uint32_t prev)
{
	return (int64_t) curr - (int64_t) prev < -4252017623LL;
}

void PSTATSPlugin::update_record(RecordExtPSTATS* pstats_data, const Packet& pkt)
{
	/**
	 * 0 - client -> server
	 * 1 - server -> client
	 */
	int8_t dir = pkt.source_pkt ? 0 : 1;
	if (skip_dup_pkts && pkt.ip_proto == IPPROTO_TCP) {
		// Current seq <= previous ack?
		bool seq_susp = (pkt.tcp_seq <= pstats_data->tcp_seq[dir]
						 && !seq_overflowed(pkt.tcp_seq, pstats_data->tcp_seq[dir]))
			|| (pkt.tcp_seq > pstats_data->tcp_seq[dir]
				&& seq_overflowed(pkt.tcp_seq, pstats_data->tcp_seq[dir]));
		// Current ack <= previous ack?
		bool ack_susp = (pkt.tcp_ack <= pstats_data->tcp_ack[dir]
						 && !seq_overflowed(pkt.tcp_ack, pstats_data->tcp_ack[dir]))
			|| (pkt.tcp_ack > pstats_data->tcp_ack[dir]
				&& seq_overflowed(pkt.tcp_ack, pstats_data->tcp_ack[dir]));
		if (seq_susp && ack_susp && pkt.payload_len == pstats_data->tcp_len[dir]
			&& pkt.tcp_flags == pstats_data->tcp_flg[dir] && pstats_data->pkt_count != 0) {
			return;
		}
	}
	pstats_data->tcp_seq[dir] = pkt.tcp_seq;
	pstats_data->tcp_ack[dir] = pkt.tcp_ack;
	pstats_data->tcp_len[dir] = pkt.payload_len;
	pstats_data->tcp_flg[dir] = pkt.tcp_flags;

	if (pkt.payload_len_wire == 0 && use_zeros == false) {
		return;
	}

	/*
	 * dir =  1 iff client -> server
	 * dir = -1 iff server -> client
	 */
	dir = pkt.source_pkt ? 1 : -1;
	if (pstats_data->pkt_count < PSTATS_MAXELEMCOUNT) {
		uint16_t pkt_cnt = pstats_data->pkt_count;
		pstats_data->pkt_sizes[pkt_cnt] = pkt.payload_len_wire;
		pstats_data->pkt_tcp_flgs[pkt_cnt] = pkt.tcp_flags;

		pstats_data->pkt_timestamps[pkt_cnt] = pkt.ts;

		DEBUG_MSG(
			"PSTATS processed packet %d: Size: %d Timestamp: %ld.%ld\n",
			pkt_cnt,
			pstats_data->pkt_sizes[pkt_cnt],
			pstats_data->pkt_timestamps[pkt_cnt].tv_sec,
			pstats_data->pkt_timestamps[pkt_cnt].tv_usec);

		pstats_data->pkt_dirs[pkt_cnt] = dir;
		pstats_data->pkt_count++;
	} else {
		/* Do not count more than PSTATS_MAXELEMCOUNT packets */
	}
}

ProcessPlugin::FlowAction PSTATSPlugin::post_create(Flow& rec, const Packet& pkt)
{
	RecordExtPSTATS* pstats_data = new RecordExtPSTATS(m_pluginID);
	rec.add_extension(pstats_data);

	update_record(pstats_data, pkt);
	return pstats_data->pkt_count < PSTATS_MAXELEMCOUNT
		? ProcessPlugin::FlowAction::GET_ALL_DATA
		: ProcessPlugin::FlowAction::GET_NO_DATA;
}

void PSTATSPlugin::pre_export(Flow& rec)
{
	// do not export pstats for single packets flows, usually port scans
	uint32_t packets = rec.src_packets + rec.dst_packets;
	uint8_t flags = rec.src_tcp_flags | rec.dst_tcp_flags;
	if (packets <= PSTATS_MINLEN && (flags & 0x02)) { // tcp SYN set
		rec.remove_extension(m_pluginID);
	}
}

ProcessPlugin::FlowAction PSTATSPlugin::post_update(Flow& rec, const Packet& pkt)
{
	RecordExtPSTATS* pstats_data = (RecordExtPSTATS*) rec.get_extension(m_pluginID);
	update_record(pstats_data, pkt);
	return pstats_data->pkt_count < PSTATS_MAXELEMCOUNT
		? ProcessPlugin::FlowAction::GET_ALL_DATA
		: ProcessPlugin::FlowAction::GET_NO_DATA;
}

static const PluginRegistrar<PSTATSPlugin, ProcessPluginFactory>
	pstatsRegistrar(pstatsPluginManifest);

} // namespace ipxp
