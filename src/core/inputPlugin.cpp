/**
 * @file
 * @brief Implementation of InputPlugin telemetry integration
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * This file contains the implementation of telemetry-related functions for
 * the InputPlugin class. It provides functionality to register parser statistics
 * in the telemetry system and manage telemetry directories.
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <numeric>

#include <ipfixprobe/inputPlugin.hpp>

namespace ipxp {

static telemetry::Content get_parser_stats_content(const ParserStats& parserStats)
{
	telemetry::Dict dict;
	dict["mpls_packets"] = parserStats.mpls_packets;
	dict["vlan_packets"] = parserStats.vlan_packets;
	dict["pppoe_packets"] = parserStats.pppoe_packets;
	dict["trill_packets"] = parserStats.trill_packets;

	dict["ipv4_packets"] = parserStats.ipv4_packets;
	dict["ipv6_packets"] = parserStats.ipv6_packets;
	dict["ipv4_bytes"] = parserStats.ipv4_bytes;
	dict["ipv6_bytes"] = parserStats.ipv6_bytes;

	dict["tcp_packets"] = parserStats.tcp_packets;
	dict["udp_packets"] = parserStats.udp_packets;

	dict["seen_packets"] = parserStats.seen_packets;
	dict["unknown_packets"] = parserStats.unknown_packets;
	const std::vector<TopPorts::PortStats>& ports = parserStats.top_ports.get_top_ports();
	if (ports.empty()) {
		dict["top_10_ports"] = "";
	} else {
		std::string top_ports = ports[0].to_string();
		dict["top_10_ports"] = std::accumulate(
			ports.begin() + 1,
			ports.end(),
			top_ports,
			[](std::string acc, const TopPorts::PortStats& port_frequency) {
				return acc + ", " + port_frequency.to_string();
			});
	}
	return dict;
}

static telemetry::Content get_vlan_stats(const VlanStats& vlanStats)
{
	telemetry::Dict dict;
	dict["ipv4_packets"] = vlanStats.ipv4_packets;
	dict["ipv4_bytes"] = vlanStats.ipv4_bytes;
	dict["ipv6_packets"] = vlanStats.ipv6_packets;
	dict["ipv6_bytes"] = vlanStats.ipv6_bytes;
	dict["tcp_packets"] = vlanStats.tcp_packets;
	dict["udp_packets"] = vlanStats.udp_packets;
	dict["total_packets"] = vlanStats.total_packets;
	dict["total_bytes"] = vlanStats.total_bytes;
	return dict;
}

static telemetry::Content get_vlan_size_histogram_content(const PacketSizeHistogram& sizeHistogram)
{
	telemetry::Dict dict;
	for (std::size_t bucket = 0; bucket < PacketSizeHistogram::HISTOGRAM_SIZE; ++bucket) {
		const PacketSizeHistogram::Value value = sizeHistogram.get_bucket_value(bucket);
		dict["etherPacketCount[" + sizeHistogram.get_bucket_name(bucket) + "]"]
			= telemetry::ScalarWithUnit {value.packets, "packets"};
		dict["etherPacketSize[" + sizeHistogram.get_bucket_name(bucket) + "]"]
			= telemetry::ScalarWithUnit {value.bytes, "bytes"};
	}
	return dict;
}

void InputPlugin::create_parser_stats_telemetry(
	std::shared_ptr<telemetry::Directory> queueDirectory,
	std::shared_ptr<telemetry::Directory> summaryDirectory,
	std::shared_ptr<telemetry::Directory> pipelineDirectory)
{
	auto parserDir = queueDirectory->addDir("parser");
	auto summaryParserDir = summaryDirectory->addDir("parser");

	telemetry::FileOps statsOps
		= {[this]() { return get_parser_stats_content(m_parser_stats); }, nullptr};

	auto vlanStatsDir = parserDir->addDir("vlan-stats");
	for (std::size_t vlan_id = 0; vlan_id < MAX_VLAN_ID; ++vlan_id) {
		telemetry::FileOps vlanStatsOps
			= {[this, vlan_id]() { return get_vlan_stats(m_parser_stats.vlan_stats[vlan_id]); },
			   nullptr};
		telemetry::FileOps vlanHistogramOps
			= {[this, vlan_id]() {
				   return get_vlan_size_histogram_content(
					   m_parser_stats.vlan_stats[vlan_id].size_histogram);
			   },
			   nullptr};
		auto vlanIDDir = vlanStatsDir->addDir(std::to_string(vlan_id));
		auto vlanSummaryDir = summaryParserDir->addDirs("vlan-stats/" + std::to_string(vlan_id));
		register_file(vlanIDDir, "stats", vlanStatsOps);
		register_file(vlanIDDir, "histogram", vlanHistogramOps);

		const std::vector<telemetry::AggOperation> aggOps {
			{telemetry::AggMethodType::SUM, "ipv4_packets"},
			{telemetry::AggMethodType::SUM, "ipv4_bytes"},
			{telemetry::AggMethodType::SUM, "ipv6_packets"},
			{telemetry::AggMethodType::SUM, "ipv6_bytes"},
			{telemetry::AggMethodType::SUM, "tcp_packets"},
			{telemetry::AggMethodType::SUM, "udp_packets"},
			{telemetry::AggMethodType::SUM, "total_packets"},
			{telemetry::AggMethodType::SUM, "total_bytes"},
		};

		register_agg_file(
			vlanSummaryDir,
			"stats",
			R"(queues/\d+/parser/vlan-stats/)" + std::to_string(vlan_id) + R"(/stats)",
			aggOps,
			pipelineDirectory);

		std::vector<telemetry::AggOperation> aggHistogramSummaryOps;
		for (std::size_t bucket = 0; bucket < PacketSizeHistogram::HISTOGRAM_SIZE; ++bucket) {
			auto histogram = m_parser_stats.vlan_stats[vlan_id].size_histogram;
			aggHistogramSummaryOps.push_back(
				{telemetry::AggMethodType::SUM,
				 "etherPacketCount[" + histogram.get_bucket_name(bucket) + "]"});
			aggHistogramSummaryOps.push_back(
				{telemetry::AggMethodType::SUM,
				 "etherPacketSize[" + histogram.get_bucket_name(bucket) + "]"});
		}
		register_agg_file(
			vlanSummaryDir,
			"histogram",
			R"(queues/\d+/parser/vlan-stats/)" + std::to_string(vlan_id) + R"(/histogram)",
			aggHistogramSummaryOps,
			pipelineDirectory);
	}

	const std::vector<telemetry::AggOperation> aggOps {
		{telemetry::AggMethodType::SUM, "ipv4_bytes"},
		{telemetry::AggMethodType::SUM, "ipv4_packets"},
		{telemetry::AggMethodType::SUM, "ipv6_bytes"},
		{telemetry::AggMethodType::SUM, "ipv6_packets"},
		{telemetry::AggMethodType::SUM, "mpls_packets"},
		{telemetry::AggMethodType::SUM, "pppoe_packets"},
		{telemetry::AggMethodType::SUM, "seen_packets"},
		{telemetry::AggMethodType::SUM, "tcp_packets"},
		{telemetry::AggMethodType::SUM, "trill_packets"},
		{telemetry::AggMethodType::SUM, "udp_packets"},
		{telemetry::AggMethodType::SUM, "unknown_packets"},
		{telemetry::AggMethodType::SUM, "vlan_packets"},
	};

	register_agg_file(
		summaryParserDir,
		"parser-stats",
		R"(queues/\d+/parser/parser-stats)",
		aggOps,
		pipelineDirectory);

	register_file(parserDir, "parser-stats", statsOps);
}

void InputPlugin::set_telemetry_dirs(
	std::shared_ptr<telemetry::Directory> plugin_dir,
	std::shared_ptr<telemetry::Directory> queues_dir,
	std::shared_ptr<telemetry::Directory> summary_dir,
	std::shared_ptr<telemetry::Directory> pipeline_dir)
{
	create_parser_stats_telemetry(queues_dir, summary_dir, pipeline_dir);
	configure_telemetry_dirs(plugin_dir, queues_dir);
}

} // namespace ipxp
