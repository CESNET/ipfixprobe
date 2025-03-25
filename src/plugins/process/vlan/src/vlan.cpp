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

#include "vlan.hpp"

#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

static const PluginManifest vlanPluginManifest = {
	.name = "vlan",
	.description = "Vlan process plugin for parsing vlan traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage = nullptr,
};

VLANPlugin::VLANPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

ProcessPlugin* VLANPlugin::copy()
{
	return new VLANPlugin(*this);
}

int VLANPlugin::post_create(Flow& rec, const Packet& pkt)
{
	auto ext = new RecordExtVLAN(m_pluginID);
	ext->vlan_id = pkt.vlan_id;
	rec.add_extension(ext);
	return 0;
}

static const PluginRegistrar<VLANPlugin, ProcessPluginFactory> vlanRegistrar(vlanPluginManifest);

} // namespace ipxp
