/**
 * @file
 * @brief Plugin for parsing idpcontent traffic.
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "idpcontent.hpp"

#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

int RecordExtIDPCONTENT::REGISTERED_ID = ProcessPluginIDGenerator::instance().generatePluginID();

static const PluginManifest idpcontentPluginManifest = {
	.name = "idpcontent",
	.description = "Idpcontent process plugin for parsing idpcontent traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage = nullptr,
};

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

IDPCONTENTPlugin::IDPCONTENTPlugin(const std::string& params)
{
	init(params.c_str());
}

IDPCONTENTPlugin::~IDPCONTENTPlugin()
{
	close();
}

void IDPCONTENTPlugin::init(const char* params)
{
	(void) params;
}

void IDPCONTENTPlugin::close() {}

ProcessPlugin* IDPCONTENTPlugin::copy()
{
	return new IDPCONTENTPlugin(*this);
}

void IDPCONTENTPlugin::update_record(RecordExtIDPCONTENT* idpcontent_data, const Packet& pkt)
{
	// create ptr into buffers from packet directions
	uint8_t paket_direction = (uint8_t) (!pkt.source_pkt);

	// Check zero-packets and be sure, that the exported content is from both directions
	if (idpcontent_data->pkt_export_flg[paket_direction] != 1 && pkt.payload_len > 0) {
		idpcontent_data->idps[paket_direction].size = MIN(IDPCONTENT_SIZE, pkt.payload_len);
		memcpy(
			idpcontent_data->idps[paket_direction].data,
			pkt.payload,
			idpcontent_data->idps[paket_direction].size);
		idpcontent_data->pkt_export_flg[paket_direction] = 1;
	}
}

int IDPCONTENTPlugin::post_create(Flow& rec, const Packet& pkt)
{
	RecordExtIDPCONTENT* idpcontent_data = new RecordExtIDPCONTENT();
	memset(idpcontent_data->pkt_export_flg, 0, 2 * sizeof(uint8_t));
	rec.add_extension(idpcontent_data);

	update_record(idpcontent_data, pkt);
	return 0;
}

int IDPCONTENTPlugin::post_update(Flow& rec, const Packet& pkt)
{
	RecordExtIDPCONTENT* idpcontent_data
		= static_cast<RecordExtIDPCONTENT*>(rec.get_extension(RecordExtIDPCONTENT::REGISTERED_ID));
	update_record(idpcontent_data, pkt);
	return 0;
}

static const PluginRegistrar<IDPCONTENTPlugin, ProcessPluginFactory>
	idpcontentRegistrar(idpcontentPluginManifest);

} // namespace ipxp
