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

#include "ssaDetector.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils.hpp>

namespace ipxp {

static const PluginManifest ssaDetectorPluginManifest = {
	.name = "ssadetector",
	.description = "Ssadetector process plugin for parsing vpn_automaton traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser(
				"ssadetector",
				"Check traffic for SYN-SYNACK-ACK sequence to find possible network tunnels.");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<SSADetectorFields>> fields = {
	{SSADetectorFields::SSA_CONF_LEVEL, "SSA_CONF_LEVEL"},
};


static FieldSchema createSSADetectorSchema()
{
	FieldSchema schema("ssadetector");

	schema.addScalarField<uint8_t>(
		"SSA_CONF_LEVEL",
		FieldDirection::DirectionalIndifferent,
		offsetof(SSADetectorExport, confidence));

	return schema;
}

SSADetectorPlugin::SSADetectorPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createSSADetectorSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

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


inline bool SSADetectorPlugin::transition_from_syn_ack(
	RecordExtSSADetector* record,
	uint16_t len,
	const timeval& ts,
	uint8_t dir)
{
	return m_packetStorage.hasSynAck(len, SYN_ACK_LOOKUP_WINDOW, !dir, ts);
}

constexpr
void SSADetectorPlugin::updatePacketsData(
	const std::size_t length,
	const uint64_t timestamp,
	const Direction direction) noexcept
{
	if (!PacketStorage::isValid(length)) {
		return;
	}
	/**
	 * 0 - client -> server
	 * 1 - server -> client
	 */
	uint8_t dir = pkt.source_pkt ? 0 : 1;
	uint16_t len = pkt.payload_len;
	timeval ts = pkt.ts;

	constexpr std::size_t MIN_PACKET_SIZE = 60;
	constexpr std::size_t MAX_PACKET_SIZE = 150;
	if (len < MIN_PACKET_SIZE || len > MAX_PACKET_SIZE) {
		return;
	}

	constexpr std::size_t MaxSynToSynAckSizeDiff = 12;
	const bool foundTCPHandshake = m_synPackets.hasSimilarPacketsRecently(
		length, MaxSynToSynAckSizeDiff, timestamp, !direction);

	if (foundTCPHandshake) {
		record->reset();
		if (record->syn_pkts_idx < SYN_RECORDS_NUM) {
			record->syn_pkts[record->syn_pkts_idx] = len;
			record->syn_pkts_idx += 1;
		}
		record->suspects += 1;
		return;
	}

	constexpr std::size_t MaxSynAckToSynSizeDiff = 12;
	const bool correspondingSynFound = m_synPackets.hasSimilarPacketsRecently(
		length, MaxSynAckToSynSizeDiff, timestamp, !direction);
	if (correspondingSynFound) {
		m_synAckPackets.insert(length, timestamp, direction);
	}

	m_synPackets.insert(length, timestamp, direction);
}

FlowAction SSADetectorPlugin::onFlowUpdate([[maybe_unused]]FlowRecord& flowRecord, 
	const Packet& packet)
{
	constexpr std::size_t MIN_FLOW_LENGTH = 30;
	if (flowRecord.dataForward.packets + flowRecord.dataReverse.packets < MIN_FLOW_LENGTH) {
		return FlowAction::RequestTrimmedData;
	}

	updatePacketsData(packet.size(), packet.timeStamp, packet.direction);

	return FlowAction::RequestTrimmedData;
}

void SSADetectorPlugin::onFlowExport(FlowRecord& flowRecord) 
{
	// TODO makeAllAvailable();
}

ProcessPlugin* SSADetectorPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<SSADetectorPlugin*>(constructAtAddress), *this);
}

std::string SSADetectorPlugin::getName() const { 
	return ssaDetectorPluginManifest.name; 
}

const void* SSADetectorPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<SSADetectorPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ssaDetectorRegistrar(ssaDetectorPluginManifest);

} // namespace ipxp
