/**
 * @file
 * @brief Plugin for parsing phists traffic.
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "phists.hpp"

#include <algorithm>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <math.h>

namespace ipxp {

int RecordExtPHISTS::REGISTERED_ID = ProcessPluginIDGenerator::instance().generatePluginID();

static const PluginManifest phistsPluginManifest = {
	.name = "phists",
	.description = "Phists process plugin for parsing phists traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			PHISTSOptParser parser;
			parser.usage(std::cout);
		},
};

#define PHISTS_INCLUDE_ZEROS_OPT "includezeros"

#ifdef DEBUG_PHISTS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

const uint32_t PHISTSPlugin::log2_lookup32[32]
	= {0, 9,  1,  10, 13, 21, 2,  29, 11, 14, 16, 18, 22, 25, 3, 30,
	   8, 12, 20, 28, 15, 17, 24, 7,  19, 27, 23, 6,  26, 5,  4, 31};

PHISTSPlugin::PHISTSPlugin(const std::string& params)
	: use_zeros(false)
{
	init(params.c_str());
}

PHISTSPlugin::~PHISTSPlugin()
{
	close();
}

void PHISTSPlugin::init(const char* params)
{
	PHISTSOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	use_zeros = parser.m_include_zeroes;
}

void PHISTSPlugin::close() {}

ProcessPlugin* PHISTSPlugin::copy()
{
	return new PHISTSPlugin(*this);
}

/*
 * 0-15     1. bin
 * 16-31    2. bin
 * 32-63    3. bin
 * 64-127   4. bin
 * 128-255  5. bin
 * 256-511  6. bin
 * 512-1023 7. bin
 * 1024 >   8. bin
 */
void PHISTSPlugin::update_hist(RecordExtPHISTS* phists_data, uint32_t value, uint32_t* histogram)
{
	(void) phists_data;
	if (value < 16) {
		histogram[0] = no_overflow_increment(histogram[0]);
	} else if (value > 1023) {
		histogram[HISTOGRAM_SIZE - 1] = no_overflow_increment(histogram[HISTOGRAM_SIZE - 1]);
	} else {
		histogram[fastlog2_32(value) - 2 - 1] = no_overflow_increment(
			histogram[fastlog2_32(value) - 2 - 1]); // -2 means shift cause first bin corresponds to
													// 2^4
	}
	return;
}

int64_t PHISTSPlugin::calculate_ipt(
	RecordExtPHISTS* phists_data,
	const struct timeval tv,
	uint8_t direction)
{
	int64_t ts = IpfixBasicList::Tv2Ts(tv);

	if (phists_data->last_ts[direction] == 0) {
		phists_data->last_ts[direction] = ts;
		return -1;
	}
	int64_t diff = ts - phists_data->last_ts[direction];
	phists_data->last_ts[direction] = ts;
	if (diff < 0) {
		diff = 0;
	}
	return (int64_t) diff;
}

void PHISTSPlugin::update_record(RecordExtPHISTS* phists_data, const Packet& pkt)
{
	if (pkt.payload_len_wire == 0 && use_zeros == false) {
		return;
	}
	uint8_t direction = (uint8_t) !pkt.source_pkt;
	update_hist(phists_data, (uint32_t) pkt.payload_len_wire, phists_data->size_hist[direction]);
	int32_t ipt_diff = (int32_t) calculate_ipt(phists_data, pkt.ts, direction);
	if (ipt_diff != -1) {
		update_hist(phists_data, (uint32_t) ipt_diff, phists_data->ipt_hist[direction]);
	}
}

void PHISTSPlugin::pre_export(Flow& rec)
{
	// do not export phists for single packets flows, usually port scans
	uint32_t packets = rec.src_packets + rec.dst_packets;
	uint8_t flags = rec.src_tcp_flags | rec.dst_tcp_flags;

	if (packets <= PHISTS_MINLEN && (flags & 0x02)) { // tcp SYN set
		rec.remove_extension(RecordExtPHISTS::REGISTERED_ID);
	}
}

int PHISTSPlugin::post_create(Flow& rec, const Packet& pkt)
{
	RecordExtPHISTS* phists_data = new RecordExtPHISTS();

	rec.add_extension(phists_data);

	update_record(phists_data, pkt);
	return 0;
}

int PHISTSPlugin::post_update(Flow& rec, const Packet& pkt)
{
	RecordExtPHISTS* phists_data
		= (RecordExtPHISTS*) rec.get_extension(RecordExtPHISTS::REGISTERED_ID);

	update_record(phists_data, pkt);
	return 0;
}

static const PluginRegistrar<PHISTSPlugin, ProcessPluginFactory>
	phistsRegistrar(phistsPluginManifest);

} // namespace ipxp
