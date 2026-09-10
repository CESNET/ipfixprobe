/**
 * @file
 * @brief Plugin for parsing packet info arriving via the "sock" input plugin.
 * @author Lokesh Dhoundiyal <lokesh.dhoundial@alliedtelesis.co.nz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "sockpktinfo.hpp"

#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

static const PluginManifest sockpktinfoPluginManifest = {
	.name = "sockpktinfo",
	.description = "Sock input plugin packet information process plugin.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser(
				"sockpktinfo",
				"Process additional information coming in via the sock input plugin use");
			parser.usage(std::cout);
		},
};

SOCKPKTINFOPlugin::SOCKPKTINFOPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

ProcessPlugin* SOCKPKTINFOPlugin::copy()
{
	return new SOCKPKTINFOPlugin(*this);
}

int SOCKPKTINFOPlugin::post_create(Flow& rec, const Packet& pkt)
{
	auto ext = new RecordExtSOCKPKTINFO(m_pluginID);
	ext->ing_phy_interface = pkt.source_interface;
	ext->drop_packets = pkt.drop_cnt;

	/* Update packet count and byte count received from sock input plugin */
	rec.src_packets = pkt.pkt_cnt;
	rec.src_bytes = pkt.byte_cnt;
	rec.add_extension(ext);
	return FLOW_FLUSH;
}

static const PluginRegistrar<SOCKPKTINFOPlugin, ProcessPluginFactory>
	sockpktinfoRegistrar(sockpktinfoPluginManifest);

} // namespace ipxp
