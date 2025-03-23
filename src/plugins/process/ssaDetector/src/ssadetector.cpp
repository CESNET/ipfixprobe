/**
 * @file
 * @brief Plugin for parsing vpn_automaton traffic.
 * @author Karel Hynek hynekkar@cesnet.cz
 * @author Jan Jirák jirakja7@fit.cvut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ssadetector.hpp"

#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

static const PluginManifest ssadetectorPluginManifest = {
	.name = "ssadetector",
	.description = "Ssadetector process plugin for parsing vpn_automaton traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage = nullptr,
};

SSADetectorPlugin::SSADetectorPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

SSADetectorPlugin::~SSADetectorPlugin()
{
	close();
}

void SSADetectorPlugin::init(const char* params)
{
	(void) params;
}

void SSADetectorPlugin::close() {}

ProcessPlugin* SSADetectorPlugin::copy()
{
	return new SSADetectorPlugin(*this);
}

inline void SSADetectorPlugin::transition_from_init(
	RecordExtSSADetector* record,
	uint16_t len,
	const timeval& ts,
	uint8_t dir)
{
	record->syn_table.update_entry(len, dir, ts);
}

inline void SSADetectorPlugin::transition_from_syn(
	RecordExtSSADetector* record,
	uint16_t len,
	const timeval& ts,
	uint8_t dir)
{
	bool can_transit = record->syn_table.check_range_for_presence(len, SYN_LOOKUP_WINDOW, !dir, ts);
	if (can_transit) {
		record->syn_ack_table.update_entry(len, dir, ts);
	}
}

inline bool SSADetectorPlugin::transition_from_syn_ack(
	RecordExtSSADetector* record,
	uint16_t len,
	const timeval& ts,
	uint8_t dir)
{
	return record->syn_table.check_range_for_presence(len, SYN_ACK_LOOKUP_WINDOW, !dir, ts);
}

void SSADetectorPlugin::update_record(RecordExtSSADetector* record, const Packet& pkt)
{
	/**
	 * 0 - client -> server
	 * 1 - server -> client
	 */
	uint8_t dir = pkt.source_pkt ? 0 : 1;
	uint16_t len = pkt.payload_len;
	timeval ts = pkt.ts;

	if (!(MIN_PKT_SIZE <= len && len <= MAX_PKT_SIZE)) {
		return;
	}

	bool reached_end_state = transition_from_syn_ack(record, len, ts, dir);

	if (reached_end_state) {
		record->reset();
		if (record->syn_pkts_idx < SYN_RECORDS_NUM) {
			record->syn_pkts[record->syn_pkts_idx] = len;
			record->syn_pkts_idx += 1;
		}
		record->suspects += 1;
		return;
	}

	transition_from_syn(record, len, ts, dir);
	transition_from_init(record, len, ts, dir);
}

int SSADetectorPlugin::post_update(Flow& rec, const Packet& pkt)
{
	RecordExtSSADetector* record = nullptr;
	if (rec.src_packets + rec.dst_packets < MIN_PKT_IN_FLOW) {
		return 0;
	}

	record = (RecordExtSSADetector*) rec.get_extension(m_pluginID);
	if (record == nullptr) {
		record = new RecordExtSSADetector(m_pluginID);
		rec.add_extension(record);
	}

	update_record(record, pkt);
	return 0;
}

double classes_ratio(uint8_t* syn_pkts, uint8_t size)
{
	uint8_t unique_members = 0;
	bool marked[size];
	for (uint8_t i = 0; i < size; ++i)
		marked[i] = false;
	for (uint8_t i = 0; i < size; ++i) {
		if (marked[i]) {
			continue;
		}
		uint8_t akt_pkt_size = syn_pkts[i];
		unique_members++;
		marked[i] = true;
		for (uint8_t j = i + 1; j < size; ++j) {
			if (marked[j]) {
				continue;
			}
			if (syn_pkts[j] == akt_pkt_size) {
				marked[j] = true;
			}
		}
	}

	return double(unique_members) / double(size);
}

void SSADetectorPlugin::pre_export(Flow& rec)
{
	// do not export for small packets flows
	uint32_t packets = rec.src_packets + rec.dst_packets;
	if (packets <= MIN_PKT_IN_FLOW) {
		rec.remove_extension(m_pluginID);
		return;
	}

	RecordExtSSADetector* record = (RecordExtSSADetector*) rec.get_extension(m_pluginID);
	const auto& suspects = record->suspects;
	if (suspects < MIN_NUM_SUSPECTS) {
		return;
	}
	if (double(packets) / double(suspects) > MIN_SUSPECTS_RATIO) {
		return;
	}
	if (suspects < LOW_NUM_SUSPECTS_THRESHOLD) {
		if (classes_ratio(record->syn_pkts, record->syn_pkts_idx) > LOW_NUM_SUSPECTS_MAX_RATIO) {
			return;
		}
	} else if (suspects < MID_NUM_SUSPECTS_THRESHOLD) {
		if (classes_ratio(record->syn_pkts, record->syn_pkts_idx) > MID_NUM_SUSPECTS_MAX_RATIO) {
			return;
		}
	} else {
		if (classes_ratio(record->syn_pkts, record->syn_pkts_idx) > HIGH_NUM_SUSPECTS_MAX_RATIO) {
			return;
		}
	}

	record->possible_vpn = 1;
}

//--------------------RecordExtSSADetector::pkt_entry-------------------------------
void RecordExtSSADetector::pkt_entry::reset()
{
	ts_dir1.tv_sec = 0;
	ts_dir1.tv_usec = 0;
	ts_dir2.tv_sec = 0;
	ts_dir2.tv_usec = 0;
}

timeval& RecordExtSSADetector::pkt_entry::get_time(dir_t dir)
{
	return (dir == 1) ? ts_dir1 : ts_dir2;
}

RecordExtSSADetector::pkt_entry::pkt_entry()
{
	reset();
}

//--------------------RecordExtSSADetector::pkt_table-------------------------------
void RecordExtSSADetector::pkt_table::reset()
{
	for (int i = 0; i < PKT_TABLE_SIZE; ++i) {
		table_[i].reset();
	}
}

bool RecordExtSSADetector::pkt_table::check_range_for_presence(
	uint16_t len,
	uint8_t down_by,
	dir_t dir,
	const timeval& ts_to_compare)
{
	int8_t idx = get_idx_from_len(len);
	for (int8_t i = std::max(idx - down_by, 0); i <= idx; ++i) {
		if (entry_is_present(i, dir, ts_to_compare)) {
			return true;
		}
	}
	return false;
}

void RecordExtSSADetector::pkt_table::update_entry(uint16_t len, dir_t dir, timeval ts)
{
	int8_t idx = get_idx_from_len(len);
	if (dir == 1) {
		table_[idx].ts_dir1 = ts;
	} else {
		table_[idx].ts_dir2 = ts;
	}
}

bool RecordExtSSADetector::pkt_table::time_in_window(const timeval& ts_now, const timeval& ts_old)
{
	long diff_secs = ts_now.tv_sec - ts_old.tv_sec;
	long diff_micro_secs = ts_now.tv_usec - ts_old.tv_usec;

	diff_micro_secs += diff_secs * 1000000;
	if (diff_micro_secs > MAX_TIME_WINDOW) {
		return false;
	}
	return true;
}

bool RecordExtSSADetector::pkt_table::entry_is_present(
	int8_t idx,
	dir_t dir,
	const timeval& ts_to_compare)
{
	timeval& ts = table_[idx].get_time(dir);
	if (time_in_window(ts_to_compare, ts)) {
		return true;
	}
	return false;
}

int8_t RecordExtSSADetector::pkt_table::get_idx_from_len(uint16_t len)
{
	return std::max(int(len) - MIN_PKT_SIZE, 0);
}

static const PluginRegistrar<SSADetectorPlugin, ProcessPluginFactory>
	ssadetectorRegistrar(ssadetectorPluginManifest);

} // namespace ipxp
