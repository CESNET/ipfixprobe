/**
 * \file
 * \brief
 * \author Pavel Siska <siska@cesnet.cz>
 * \date 2024
 */
/*
 * Copyright (C) 2024 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 */

#include <ipfixprobe/input.hpp>

namespace ipxp {

InputPlugin::InputPlugin()
	: m_seen(0)
	, m_parsed(0)
	, m_dropped(0)
	, m_parser_stats()
{
}

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
		= {[=]() { return get_parser_stats_content(m_parser_stats); }, nullptr};
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