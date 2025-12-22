/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "qinq.hpp"

#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

static const PluginManifest qinqPluginManifest = {
	.name = "qinq",
	.description = "QinQ process plugin for parsing QinQ traffic, outputs outer and inner VLAN IDs.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("qinq", "Parse qinq traffic");
			parser.usage(std::cout);
		},
};

QinQPlugin::QinQPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

ProcessPlugin* QinQPlugin::copy()
{
	return new QinQPlugin(*this);
}

int QinQPlugin::post_create(Flow& rec, const Packet& pkt)
{
	auto ext = new RecordExtQinQ(m_pluginID);
	ext->vlan_id = pkt.vlan_id;
	ext->vlan_id2 = pkt.vlan_id2;
	rec.add_extension(ext);
	return 0;
}

static const PluginRegistrar<QinQPlugin, ProcessPluginFactory> qinqRegistrar(qinqPluginManifest);

} // namespace ipxp
