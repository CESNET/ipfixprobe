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

#pragma once

#include "ndpReader.hpp"

#include <memory>
#include <span>

#include <ipfixprobe/inputPlugin.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

class NdpOptParser : public OptionsParser {
public:
	std::string m_dev;
	uint64_t m_id;

	NdpOptParser()
		: OptionsParser("ndp", "Input plugin for reading packets from a ndp device")
		, m_dev("")
		, m_id(0)
	{
		register_option(
			"d",
			"dev",
			"PATH",
			"Path to a device file",
			[this](const char* arg) {
				m_dev = arg;
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"I",
			"id",
			"NUM",
			"Link identifier number",
			[this](const char* arg) {
				try {
					m_id = str2num<decltype(m_id)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
	}
};

class NdpPacketReader : public InputPlugin {
public:
	NdpPacketReader(const std::string& params);
	~NdpPacketReader();

	void init(const char* params);
	void close();
	OptionsParser* get_parser() const { return new NdpOptParser(); }
	std::string get_name() const { return "ndp"; }
	InputPlugin::Result get(PacketBlock& packets);

	void configure_telemetry_dirs(
		std::shared_ptr<telemetry::Directory> plugin_dir,
		std::shared_ptr<telemetry::Directory> queues_dir) override;

private:
	struct RxStats {
		uint64_t receivedPackets;
		uint64_t receivedBytes;
	};

	telemetry::Content get_queue_telemetry();

	NdpReader ndpReader[2];
	std::size_t m_readers_count;
	uint64_t m_reader_idx = 0;
	RxStats m_stats = {};

	std::unique_ptr<struct ndp_packet[]> ndp_packet_burst;
	std::array<timeval, 64> timestamps;

	void init_ifc(const std::string& dev);
};

} // namespace ipxp
