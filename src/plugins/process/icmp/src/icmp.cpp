/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "icmp.hpp"

#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

int RecordExtICMP::REGISTERED_ID = ProcessPluginIDGenerator::instance().generatePluginID();

static const PluginManifest icmpPluginManifest = {
	.name = "icmp",
	.description = "ICMP process plugin for parsing icmp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage = nullptr,
};

ICMPPlugin::ICMPPlugin(const std::string& params)
{
	(void) params;
}

ProcessPlugin* ICMPPlugin::copy()
{
	return new ICMPPlugin(*this);
}

int ICMPPlugin::post_create(Flow& rec, const Packet& pkt)
{
	if (pkt.ip_proto == IPPROTO_ICMP || pkt.ip_proto == IPPROTO_ICMPV6) {
		if (pkt.payload_len < sizeof(RecordExtICMP::type_code))
			return 0;

		auto ext = new RecordExtICMP();

		// the type and code are the first two bytes, type on MSB and code on LSB
		// in the network byte order
		ext->type_code = *reinterpret_cast<const uint16_t*>(pkt.payload);

		rec.add_extension(ext);
	}
	return 0;
}

static const PluginRegistrar<ICMPPlugin, ProcessPluginFactory> icmpRegistrar(icmpPluginManifest);

} // namespace ipxp
