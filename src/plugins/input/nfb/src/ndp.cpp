/**
 * @file
 * @brief Packet reader using NDP library for high speed capture.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Tomas Benes <benesto@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ndp.hpp"

#include "parser.hpp"

#include <cstdio>
#include <cstring>
#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

telemetry::Content NdpPacketReader::get_queue_telemetry()
{
	telemetry::Dict dict;
	dict["received_packets"] = m_stats.receivedPackets;
	dict["received_bytes"] = m_stats.receivedBytes;
	return dict;
}

static const PluginManifest ndpPluginManifest = {
	.name = "ndp",
	.description = "Ndp input plugin for reading packets from network interface or ndp file.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			NdpOptParser parser;
			parser.usage(std::cout);
		},
};

NdpPacketReader::NdpPacketReader(const std::string& params)
{
	init(params.c_str());
}

NdpPacketReader::~NdpPacketReader()
{
	close();
}

void NdpPacketReader::init(const char* params)
{
	NdpOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	if (parser.m_dev.empty()) {
		throw PluginError("specify device path");
	}
	init_ifc(parser.m_dev);
}

void NdpPacketReader::close()
{
	ndpReader.close();
}

void NdpPacketReader::init_ifc(const std::string& dev)
{
	if (ndpReader.init_interface(dev) != 0) {
		throw PluginError(ndpReader.error_msg);
	}
}

InputPlugin::Result NdpPacketReader::get(PacketBlock& packets)
{
	parser_opt_t opt = {&packets, false, false, 0};
	struct ndp_packet* ndp_packet;
	struct timeval timestamp;
	size_t read_pkts = 0;
	int ret = -1;

	packets.cnt = 0;
	for (unsigned i = 0; i < packets.size; i++) {
		ret = ndpReader.get_pkt(&ndp_packet, &timestamp);
		if (ret == 0) {
			if (opt.pblock->cnt) {
				break;
			}
			return Result::TIMEOUT;
		} else if (ret < 0) {
			// Error occured.
			throw PluginError(ndpReader.error_msg);
		}
		read_pkts++;
		parse_packet(
			&opt,
			m_parser_stats,
			timestamp,
			ndp_packet->data,
			ndp_packet->data_length,
			ndp_packet->data_length);
	}

	m_seen += read_pkts;
	m_parsed += opt.pblock->cnt;

	m_stats.receivedPackets += read_pkts;
	m_stats.receivedBytes += packets.bytes;

	return opt.pblock->cnt ? Result::PARSED : Result::NOT_PARSED;
}

void NdpPacketReader::configure_telemetry_dirs(
	std::shared_ptr<telemetry::Directory> plugin_dir,
	std::shared_ptr<telemetry::Directory> queues_dir)
{
	(void) plugin_dir;

	telemetry::FileOps statsOps = {[&]() { return get_queue_telemetry(); }, nullptr};
	register_file(queues_dir, "input-stats", statsOps);
}

static const PluginRegistrar<NdpPacketReader, InputPluginFactory> ndpRegistrar(ndpPluginManifest);

} // namespace ipxp
