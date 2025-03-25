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

	dict["tcp_packets"] = parserStats.tcp_packets;
	dict["udp_packets"] = parserStats.udp_packets;

	dict["seen_packets"] = parserStats.seen_packets;
	dict["unknown_packets"] = parserStats.unknown_packets;

	return dict;
}

void InputPlugin::create_parser_stats_telemetry(
	std::shared_ptr<telemetry::Directory> queueDirectory)
{
	telemetry::FileOps statsOps
		= {[this]() { return get_parser_stats_content(m_parser_stats); }, nullptr};
	register_file(queueDirectory, "parser-stats", statsOps);
}

void InputPlugin::set_telemetry_dirs(
	std::shared_ptr<telemetry::Directory> plugin_dir,
	std::shared_ptr<telemetry::Directory> queues_dir)
{
	create_parser_stats_telemetry(queues_dir);
	configure_telemetry_dirs(plugin_dir, queues_dir);
}

} // namespace ipxp
