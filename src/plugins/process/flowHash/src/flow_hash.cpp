/**
 * @file
 * @brief Plugin for processing flow_hash value.
 * @author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "flow_hash.hpp"

#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

static const PluginManifest flowhashPluginManifest = {
	.name = "flowhash",
	.description = "flowhash process plugin for parsing flowhash value.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("flowhash", "Export flow hash as flow id");
			parser.usage(std::cout);
		},
};

FLOW_HASHPlugin::FLOW_HASHPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

FLOW_HASHPlugin::~FLOW_HASHPlugin() {}

void FLOW_HASHPlugin::init(const char* params)
{
	(void) params;
}

void FLOW_HASHPlugin::close() {}

ProcessPlugin* FLOW_HASHPlugin::copy()
{
	return new FLOW_HASHPlugin(*this);
}

int FLOW_HASHPlugin::post_create(Flow& rec, const Packet& pkt)
{
	(void) pkt;
	auto ext = new RecordExtFLOW_HASH(m_pluginID);

	ext->flow_hash = rec.flow_hash;

	rec.add_extension(ext);

	return 0;
}

static const PluginRegistrar<FLOW_HASHPlugin, ProcessPluginFactory>
	flowhashRegistrar(flowhashPluginManifest);

} // namespace ipxp
