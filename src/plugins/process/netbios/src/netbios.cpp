/**
 * @file
 * @brief Plugin for parsing netbios traffic.
 * @author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "netbios.hpp"

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

static const PluginManifest netbiosPluginManifest = {
	.name = "netbios",
	.description = "Netbios process plugin for parsing netbios traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("netbios", "Parse netbios traffic");
			parser.usage(std::cout);
		},
};
NETBIOSPlugin::NETBIOSPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
	, total_netbios_packets(0)
{
	init(params.c_str());
}

NETBIOSPlugin::~NETBIOSPlugin()
{
	close();
}

void NETBIOSPlugin::init(const char* params)
{
	(void) params;
}

void NETBIOSPlugin::close() {}

ProcessPlugin* NETBIOSPlugin::copy()
{
	return new NETBIOSPlugin(*this);
}

ProcessPlugin::FlowAction NETBIOSPlugin::post_create(Flow& rec, const Packet& pkt)
{
	if (pkt.dst_port == 137 || pkt.src_port == 137) {
		return add_netbios_ext(rec, pkt);
	}

	return ProcessPlugin::FlowAction::GET_NO_DATA;
}

ProcessPlugin::FlowAction NETBIOSPlugin::post_update(Flow& rec, const Packet& pkt)
{
	if (pkt.dst_port == 137 || pkt.src_port == 137) {
		return add_netbios_ext(rec, pkt);
	}

	return ProcessPlugin::FlowAction::GET_NO_DATA;
}

ProcessPlugin::FlowAction NETBIOSPlugin::add_netbios_ext(Flow& rec, const Packet& pkt)
{
	RecordExtNETBIOS* ext = new RecordExtNETBIOS(m_pluginID);
	if (parse_nbns(ext, pkt)) {
		total_netbios_packets++;
		rec.add_extension(ext);
		return ProcessPlugin::FlowAction::GET_ALL_DATA;
	}
	delete ext;
	return ProcessPlugin::FlowAction::GET_NO_DATA;
}

bool NETBIOSPlugin::parse_nbns(RecordExtNETBIOS* rec, const Packet& pkt)
{
	const char* payload = reinterpret_cast<const char*>(pkt.payload);

	int qry_cnt = get_query_count(payload, pkt.payload_len);
	payload += sizeof(struct dns_hdr);
	if (qry_cnt < 1) {
		return false;
	}

	return store_first_query(payload, rec);
}

int NETBIOSPlugin::get_query_count(const char* payload, uint16_t payload_length)
{
	if (payload_length < sizeof(struct dns_hdr)) {
		return -1;
	}

	struct dns_hdr* hdr = (struct dns_hdr*) payload;
	return ntohs(hdr->question_rec_cnt);
}

bool NETBIOSPlugin::store_first_query(const char* payload, RecordExtNETBIOS* rec)
{
	uint8_t nb_name_length = *payload++;
	if (nb_name_length != 32) {
		return false;
	}

	rec->netbios_name = "";
	for (int i = 0; i < nb_name_length; i += 2, payload += 2) {
		if (i != 30) {
			rec->netbios_name += compress_nbns_name_char(payload);
		} else {
			rec->netbios_suffix = get_nbns_suffix(payload);
		}
	}
	return true;
}

char NETBIOSPlugin::compress_nbns_name_char(const char* uncompressed)
{
	return (((uncompressed[0] - 'A') << 4) | (uncompressed[1] - 'A'));
}

uint8_t NETBIOSPlugin::get_nbns_suffix(const char* uncompressed)
{
	return compress_nbns_name_char(uncompressed);
}

void NETBIOSPlugin::finish(bool print_stats)
{
	if (print_stats) {
		std::cout << "NETBIOS plugin stats:" << std::endl;
		std::cout << "   Parsed NBNS packets in total: " << total_netbios_packets << std::endl;
	}
}

static const PluginRegistrar<NETBIOSPlugin, ProcessPluginFactory>
	netbiosRegistrar(netbiosPluginManifest);

} // namespace ipxp
