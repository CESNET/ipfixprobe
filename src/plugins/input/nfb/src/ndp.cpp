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

static std::vector<std::string> parseDevices(const std::string& input)
{
	std::vector<std::string> result;

	size_t colon_pos = input.find(':');
	std::string suffix;
	std::string devices;

	if (colon_pos != std::string::npos) {
		devices = input.substr(0, colon_pos);
		suffix = input.substr(colon_pos);
	} else {
		devices = input;
		suffix = "";
	}

	std::stringstream ss(devices);
	std::string dev;
	while (std::getline(ss, dev, ',')) {
		result.push_back(dev + suffix);
	}

	return result;
}

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
	for (size_t i = 0; i < m_readers_count; i++) {
		ndpReader[i].close();
	}
}

void NdpPacketReader::init_ifc(const std::string& dev)
{
	const std::vector<std::string> devs = parseDevices(dev);
	m_readers_count = devs.size();
	if (m_readers_count > 2) {
		throw PluginError("too many devices specified");
	}

	for (size_t i = 0; i < m_readers_count; i++) {
		if (ndpReader[i].init_interface(devs[i]) != 0) {
			throw PluginError(ndpReader[i].error_msg);
		}
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

	bool any_timeout = false;

	for (unsigned r = 0; r < m_readers_count; ++r) {
		NdpReader& reader = ndpReader[(m_reader_idx++) % m_readers_count];

		for (unsigned i = 0; i < packets.size; ++i) {
			ret = reader.get_pkt(&ndp_packet, &timestamp);
			if (ret == 0) {
				any_timeout = true;
				break;
			} else if (ret < 0) {
				// Error occured.
				throw PluginError(reader.error_msg);
			}

			++read_pkts;
			parse_packet(
				&opt,
				m_parser_stats,
				timestamp,
				ndp_packet->data,
				ndp_packet->data_length,
				ndp_packet->data_length);

			if (opt.pblock->cnt >= packets.size) {
				break;
			}
		}

		if (opt.pblock->cnt) {
			break;
		}
	}

	m_seen += read_pkts;
	m_parsed += opt.pblock->cnt;

	m_stats.receivedPackets += read_pkts;
	m_stats.receivedBytes += packets.bytes;

	if (opt.pblock->cnt) {
		return Result::PARSED;
	} else if (any_timeout) {
		return Result::TIMEOUT;
	} else {
		return Result::NOT_PARSED;
	}
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
