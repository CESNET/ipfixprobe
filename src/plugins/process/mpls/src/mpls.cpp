/**
 * @file
 * @brief Plugin for parsing mpls traffic.
 * @author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mpls.hpp"

#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

static const PluginManifest mplsPluginManifest = {
	.name = "mpls",
	.description = "Mpls process plugin for parsing mpls traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage = nullptr,
};

MPLSPlugin::MPLSPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

ProcessPlugin* MPLSPlugin::copy()
{
	return new MPLSPlugin(*this);
}

int MPLSPlugin::post_create(Flow& rec, const Packet& pkt)
{
	if (pkt.mplsTop == 0) {
		return 0;
	}

	auto ext = new RecordExtMPLS(m_pluginID);
	ext->mpls = pkt.mplsTop;

	rec.add_extension(ext);
	return 0;
}

static const PluginRegistrar<MPLSPlugin, ProcessPluginFactory> mplsRegistrar(mplsPluginManifest);

} // namespace ipxp
