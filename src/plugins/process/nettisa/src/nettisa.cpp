/**
 * @file
 * @brief Plugin for parsing Nettisa flow.
 * @author Josef Koumar koumajos@fit.cvut.cz
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "nettisa.hpp"

#include <cmath>
#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

static const PluginManifest nettisaPluginManifest = {
	.name = "nettisa",
	.description = "Nettisa process plugin for parsing Nettisa flow.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("nettisa", "Parse NetTiSA flow");
			parser.usage(std::cout);
		},
};

NETTISAPlugin::NETTISAPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

ProcessPlugin* NETTISAPlugin::copy()
{
	return new NETTISAPlugin(*this);
}

void NETTISAPlugin::update_record(
	RecordExtNETTISA* nettisa_data,
	const Packet& pkt,
	const Flow& rec)
{
	float variation_from_mean = pkt.payload_len_wire - nettisa_data->mean;
	uint32_t n = rec.dst_packets + rec.src_packets;
	uint64_t packet_time = timeval2usec(pkt.ts);
	uint64_t record_time = timeval2usec(rec.time_first);
	float diff_time = fmax(packet_time - nettisa_data->prev_time, 0);
	nettisa_data->sum_payload += pkt.payload_len_wire;
	nettisa_data->prev_time = packet_time;
	// MEAN
	nettisa_data->mean += (variation_from_mean) / n;
	// MIN
	nettisa_data->min = std::min(nettisa_data->min, pkt.payload_len_wire);
	// MAX
	nettisa_data->max = std::max(nettisa_data->max, pkt.payload_len_wire);
	// ROOT MEAN SQUARE
	nettisa_data->root_mean_square += pow(pkt.payload_len_wire, 2);
	// AVERAGE DISPERSION
	nettisa_data->average_dispersion += abs(variation_from_mean);
	// KURTOSIS
	nettisa_data->kurtosis += pow(variation_from_mean, 4);
	// MEAN SCALED TIME
	nettisa_data->mean_scaled_time
		+= (packet_time - record_time - nettisa_data->mean_scaled_time) / n;
	// MEAN TIME DIFFERENCES
	nettisa_data->mean_difftimes += (diff_time - nettisa_data->mean_difftimes) / n;
	// MIN
	nettisa_data->min_difftimes = fmin(nettisa_data->min_difftimes, diff_time);
	// MAX
	nettisa_data->max_difftimes = fmax(nettisa_data->max_difftimes, diff_time);
	// TIME DISTRIBUTION
	nettisa_data->time_distribution += abs(nettisa_data->mean_difftimes - diff_time);
	// SWITCHING RATIO
	if (nettisa_data->prev_payload != pkt.packet_len_wire) {
		nettisa_data->switching_ratio += 1;
		nettisa_data->prev_payload = pkt.packet_len_wire;
	}
}

int NETTISAPlugin::post_create(Flow& rec, const Packet& pkt)
{
	RecordExtNETTISA* nettisa_data = new RecordExtNETTISA(m_pluginID);
	rec.add_extension(nettisa_data);

	nettisa_data->prev_time = timeval2usec(pkt.ts);

	update_record(nettisa_data, pkt, rec);
	return 0;
}

int NETTISAPlugin::post_update(Flow& rec, const Packet& pkt)
{
	RecordExtNETTISA* nettisa_data = (RecordExtNETTISA*) rec.get_extension(m_pluginID);

	update_record(nettisa_data, pkt, rec);
	return 0;
}

void NETTISAPlugin::pre_export(Flow& rec)
{
	RecordExtNETTISA* nettisa_data = (RecordExtNETTISA*) rec.get_extension(m_pluginID);
	uint32_t n = rec.src_packets + rec.dst_packets;
	if (n == 1) {
		rec.remove_extension(m_pluginID);
		return;
	} else {
		nettisa_data->switching_ratio = nettisa_data->switching_ratio / n;
		nettisa_data->stdev = pow(
			(nettisa_data->root_mean_square / n) - pow(nettisa_data->sum_payload / n, 2),
			0.5);
		if (nettisa_data->stdev == 0) {
			nettisa_data->kurtosis = 0;
		} else {
			nettisa_data->kurtosis = nettisa_data->kurtosis / (n * pow(nettisa_data->stdev, 4));
		}
		nettisa_data->time_distribution = (nettisa_data->time_distribution / (n - 1))
			/ (nettisa_data->max_difftimes - nettisa_data->min);
	}
	nettisa_data->root_mean_square = pow(nettisa_data->root_mean_square / n, 0.5);
	nettisa_data->average_dispersion = nettisa_data->average_dispersion / n;
}

static const PluginRegistrar<NETTISAPlugin, ProcessPluginFactory>
	nettisaRegistrar(nettisaPluginManifest);

} // namespace ipxp
