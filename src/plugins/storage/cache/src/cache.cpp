/**
 * @file
 * @brief "NewHashTable" flow cache
 * @author Martin Zadnik <zadnik@cesnet.cz>
 * @author Vaclav Bartos <bartos@cesnet.cz>
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cache.hpp"

#include "xxhash.h"

#include <cstdlib>
#include <cstring>
#include <iostream>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <ipfixprobe/ring.h>
#include <sys/time.h>
#include <netinet/in.h>

namespace ipxp {

static const PluginManifest cachePluginManifest = {
	.name = "cache",
	.description = "Storage plugin implemented as a hash table.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			CacheOptParser parser;
			parser.usage(std::cout);
		},
};

/*FlowRecord::FlowRecord()
{
	erase();
};

FlowRecord::~FlowRecord()
{
	erase();
};*/



NHTFlowCache::NHTFlowCache(const std::string& params, ipx_ring_t* queue, ProcessPluginManager& manager)
	: StoragePlugin(manager) 
	, m_cache_size(0)
	, m_line_size(0)
	, m_line_mask(0)
	, m_line_new_idx(0)
	, m_qsize(0)
	, m_qidx(0)
	, m_timeout_idx(0)
	, m_active(0)
	, m_inactive(0)
	, m_split_biflow(false)
	, m_enable_fragmentation_cache(true)
	, m_keylen(0)
	, m_key()
	, m_key_inv()
	//, m_flow_table(nullptr)
	//, m_flow_records(nullptr)
	, m_fragmentation_cache(0, 0)
{
	set_queue(queue);
	init(params.c_str());
}

NHTFlowCache::~NHTFlowCache()
{
	close();
}

void NHTFlowCache::init(const char* params)
{
	CacheOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	m_cache_size = parser.m_cache_size;
	m_line_size = parser.m_line_size;
	m_active = parser.m_active;
	m_inactive = parser.m_inactive;
	m_qidx = 0;
	m_timeout_idx = 0;
	m_line_mask = (m_cache_size - 1) & ~(m_line_size - 1);
	m_line_new_idx = m_line_size / 2;

	if (m_export_queue == nullptr) {
		throw PluginError("output queue must be set before init");
	}

	if (m_line_size > m_cache_size) {
		throw PluginError("flow cache line size must be greater or equal to cache size");
	}
	if (m_cache_size == 0) {
		throw PluginError("flow cache won't properly work with 0 records");
	}

	try {
		std::shared_ptr<FlowRecordBuilder> builder = m_manager.rebuild();
		//m_flow_table = new FlowRecordUniquePtr[m_cache_size + m_qsize];
		std::generate_n(std::back_inserter(m_flow_table), m_cache_size + m_qsize, [&]() { return builder->build(); });
		//m_flow_records = new FlowRecord[m_cache_size + m_qsize];
		/*for (decltype(m_cache_size + m_qsize) i = 0; i < m_cache_size + m_qsize; i++) {
			m_flow_table[i] = m_flow_records + i;
		}*/
	} catch (std::bad_alloc& e) {
		throw PluginError("not enough memory for flow cache allocation");
	}

	m_split_biflow = parser.m_split_biflow;
	m_enable_fragmentation_cache = parser.m_enable_fragmentation_cache;

	if (m_enable_fragmentation_cache) {
		try {
			m_fragmentation_cache
				= FragmentationCache(parser.m_frag_cache_size, parser.m_frag_cache_timeout);
		} catch (std::bad_alloc& e) {
			throw PluginError("not enough memory for fragment cache allocation");
		}
	}

#ifdef FLOW_CACHE_STATS
	m_empty = 0;
	m_not_empty = 0;
	m_hits = 0;
	m_expired = 0;
	m_flushed = 0;
	m_lookups = 0;
	m_lookups2 = 0;
#endif /* FLOW_CACHE_STATS */
}

void NHTFlowCache::close()
{
	/*if (m_flow_records != nullptr) {
		delete[] m_flow_records;
		m_flow_records = nullptr;
	}
	if (m_flow_table != nullptr) {
		delete[] m_flow_table;
		m_flow_table = nullptr;
	}*/
}

void NHTFlowCache::set_queue(ipx_ring_t* queue)
{
	m_export_queue = queue;
	m_qsize = ipx_ring_size(queue);
}

void NHTFlowCache::export_flow(size_t index)
{
	m_total_exported++;
	update_flow_end_reason_stats(static_cast<uint8_t>(m_flow_table[index]->endReason));
	update_flow_record_stats(
		m_flow_table[index]->directionalData[Direction::Forward].packets + m_flow_table[index]->directionalData[Direction::Reverse].packets);
	m_flows_in_cache--;

	std::swap(m_flow_table[index], m_flow_table[m_cache_size + m_qidx]);
	ipx_ring_push(m_export_queue, &m_flow_table[m_cache_size + m_qidx]);
	m_flow_table[index]->erase();
	m_qidx = (m_qidx + 1) % m_qsize;
}

void NHTFlowCache::finish()
{
	for (decltype(m_cache_size) i = 0; i < m_cache_size; i++) {
		if (!m_flow_table[i]->isEmpty()) {
			//m_manager.exportFlowRecord(*m_flow_table[i]);
			//plugins_pre_export(m_flow_table[i]->m_flow);
			m_flow_table[i]->endReason = FlowEndReason::FLOW_END_FORCED;
			export_flow(i);
#ifdef FLOW_CACHE_STATS
			m_expired++;
#endif /* FLOW_CACHE_STATS */
		}
	}
}

void NHTFlowCache::flush(Packet& pkt, size_t flow_index, int ret, bool source_flow)
{
#ifdef FLOW_CACHE_STATS
	m_flushed++;
#endif /* FLOW_CACHE_STATS */

	/*if (ret == FLOW_FLUSH_WITH_REINSERT) {
		FlowRecord* flow = m_flow_table[flow_index];
		flow->m_flow.end_reason = FLOW_END_FORCED;
		ipx_ring_push(m_export_queue, &flow->m_flow);

		std::swap(m_flow_table[flow_index], m_flow_table[m_cache_size + m_qidx]);

		flow = m_flow_table[flow_index];
		flow->m_flow.remove_extensions();
		*flow = *m_flow_table[m_cache_size + m_qidx];
		m_qidx = (m_qidx + 1) % m_qsize;

		flow->m_flow.m_exts = nullptr;
		flow->reuse(); // Clean counters, set time first to last
		flow->update(pkt, source_flow); // Set new counters from packet

		ret = plugins_post_create(flow->m_flow, pkt);
		if (ret & FLOW_FLUSH) {
			flush(pkt, flow_index, ret, source_flow);
		}
	} else {
		m_flow_table[flow_index]->m_flow.end_reason = FLOW_END_FORCED;
		export_flow(flow_index);
	}*/
}

int NHTFlowCache::put_pkt(Packet& pkt)
{
	int ret = 0; //plugins_pre_create(pkt);

	if (m_enable_fragmentation_cache) {
		try_to_fill_ports_to_fragmented_packet(pkt);
	}

	if (!create_hash_key(pkt)) { // saves key value and key length into attributes NHTFlowCache::key
								 // and NHTFlowCache::m_keylen
		return 0;
	}

	prefetch_export_expired();

	uint64_t hashval = m_flowKey.hash(); 
		//= XXH64(m_key, m_keylen, 0); /* Calculates hash value from key created before. */

	FlowRecord* flow; /* Pointer to flow we will be working with. */
	bool found = false;
	bool source_flow = true;
	uint32_t line_index = hashval & m_line_mask; /* Get index of flow line. */
	uint32_t flow_index = 0;
	uint32_t next_line = line_index + m_line_size;

	/* Find existing flow record in flow cache. */
	for (flow_index = line_index; flow_index < next_line; flow_index++) {
		if (m_flow_table[flow_index]->hash == hashval) {
			found = true;
			break;
		}
	}

	/* Find inversed flow. */
	/*if (!found && !m_split_biflow) {
		uint64_t hashval_inv = XXH64(m_key_inv, m_keylen, 0);
		uint64_t line_index_inv = hashval_inv & m_line_mask;
		uint64_t next_line_inv = line_index_inv + m_line_size;
		for (flow_index = line_index_inv; flow_index < next_line_inv; flow_index++) {
			if (m_flow_table[flow_index]->hash == hashval_inv) {
				found = true;
				source_flow = false;
				hashval = hashval_inv;
				line_index = line_index_inv;
				break;
			}
		}
	}*/

	if (found) {
		/* Existing flow record was found, put flow record at the first index of flow line. */
#ifdef FLOW_CACHE_STATS
		m_lookups += (flow_index - line_index + 1);
		m_lookups2 += (flow_index - line_index + 1) * (flow_index - line_index + 1);
#endif /* FLOW_CACHE_STATS */

		flow = m_flow_table[flow_index].get();
		for (decltype(flow_index) j = flow_index; j > line_index; j--) {
			std::swap(m_flow_table[j], m_flow_table[j - 1]);
		}

		//m_flow_table[line_index] = flow;
		flow_index = line_index;
#ifdef FLOW_CACHE_STATS
		m_hits++;
#endif /* FLOW_CACHE_STATS */
	} else {
		/* Existing flow record was not found. Find free place in flow line. */
		for (flow_index = line_index; flow_index < next_line; flow_index++) {
			if (m_flow_table[flow_index]->isEmpty()) {
				found = true;
				break;
			}
		}
		if (!found) {
			/* If free place was not found (flow line is full), find
			 * record which will be replaced by new record. */
			flow_index = next_line - 1;

			// Export flow
			//plugins_pre_export(m_flow_table[flow_index]->m_flow);
			m_flow_table[flow_index]->endReason = FlowEndReason::FLOW_END_NO_RES;
			export_flow(flow_index);

#ifdef FLOW_CACHE_STATS
			m_expired++;
#endif /* FLOW_CACHE_STATS */
			uint32_t flow_new_index = line_index + m_line_new_idx;
			//flow = m_flow_table[flow_index].get();
			for (decltype(flow_index) j = flow_index; j > flow_new_index; j--) {
				std::swap(m_flow_table[j], m_flow_table[j - 1]);
			}
			flow_index = flow_new_index;
			//m_flow_table[flow_new_index] = flow;
#ifdef FLOW_CACHE_STATS
			m_not_empty++;
		} else {
			m_empty++;
#endif /* FLOW_CACHE_STATS */
		}
	}

	pkt.source_pkt = source_flow;
	flow = m_flow_table[flow_index].get();

	uint8_t flw_flags = source_flow ? flow->directionalData[Direction::Forward].tcpFlags.raw : flow->directionalData[Direction::Reverse].tcpFlags.raw;
	if ((pkt.tcp_flags & 0x02) && (flw_flags & (0x01 | 0x04))) {
		// Flows with FIN or RST TCP flags are exported when new SYN packet arrives
		m_flow_table[flow_index]->endReason = FlowEndReason::FLOW_END_EOF;
		export_flow(flow_index);
		put_pkt(pkt);
		return 0;
	}

	auto features = PacketFeatures{};
	auto context = FlowContext {
			.flowRecord = *flow,
			.packet = pkt,
			.features = features
		};
	if (flow->isEmpty()) {
		m_flows_in_cache++;
		flow->createFrom(pkt, hashval);
		m_manager.processFlowRecord(context);
		ret = 0; //plugins_post_create(flow->m_flow, pkt);

		//if (ret & FLOW_FLUSH) {
		//	export_flow(flow_index);
#ifdef FLOW_CACHE_STATS
		//	m_flushed++;
#endif /* FLOW_CACHE_STATS */
		//}
	} else {
		/* Check if flow record is expired (inactive timeout). */
		if (pkt.ts.tv_sec - flow->timeLastUpdate.toTimeval().tv_sec >= m_inactive) {
			//m_flow_table[flow_index]->endReason = get_export_reason(*flow); TODO
			//plugins_pre_export(*flow);
			export_flow(flow_index);
#ifdef FLOW_CACHE_STATS
			m_expired++;
#endif /* FLOW_CACHE_STATS */
			return put_pkt(pkt);
		}

		/* Check if flow record is expired (active timeout). */
		if (pkt.ts.tv_sec - flow->timeCreation.toTimeval().tv_sec >= m_active) {
			m_flow_table[flow_index]->endReason = FlowEndReason::FLOW_END_ACTIVE;
			//plugins_pre_export(*flow);
			export_flow(flow_index);
#ifdef FLOW_CACHE_STATS
			m_expired++;
#endif /* FLOW_CACHE_STATS */
			return put_pkt(pkt);
		}

		ret = 0; //plugins_pre_update(flow->m_flow, pkt);
		/*if (ret & FLOW_FLUSH) {
			flush(pkt, flow_index, ret, source_flow);
			return 0;
		} else {*/
			flow->update(pkt, source_flow);
			//ret = plugins_post_update(flow->m_flow, pkt);

			/*if (ret & FLOW_FLUSH) {
				flush(pkt, flow_index, ret, source_flow);
				return 0;
			}*/
		//}
	}

	export_expired(pkt.ts.tv_sec);
	return 0;
}

void NHTFlowCache::try_to_fill_ports_to_fragmented_packet(Packet& packet)
{
	m_fragmentation_cache.process_packet(packet);
}

uint8_t NHTFlowCache::get_export_reason(FlowRecord& flow)
{
	if ((flow.directionalData[Direction::Forward].tcpFlags.raw | flow.directionalData[Direction::Reverse].tcpFlags.raw) & (0x01 | 0x04)) {
		// When FIN or RST is set, TCP connection ended naturally
		return static_cast<uint8_t>(FlowEndReason::FLOW_END_EOF);
	} else {
		return static_cast<uint8_t>(FlowEndReason::FLOW_END_INACTIVE);
	}
}

void NHTFlowCache::export_expired(time_t ts)
{
	for (decltype(m_timeout_idx) i = m_timeout_idx; i < m_timeout_idx + m_line_new_idx; i++) {
		if (!m_flow_table[i]->isEmpty()
			&& ts - m_flow_table[i]->timeLastUpdate.toTimeval().tv_sec >= m_inactive) {
			m_flow_table[i]->endReason = static_cast<FlowEndReason>(get_export_reason(*m_flow_table[i]));
			//m_manager.exportFlowRecord(*m_flow_table[i]);
			//plugins_pre_export(m_flow_table[i]->m_flow);
			export_flow(i);
#ifdef FLOW_CACHE_STATS
			m_expired++;
#endif /* FLOW_CACHE_STATS */
		}
	}

	m_timeout_idx = (m_timeout_idx + m_line_new_idx) & (m_cache_size - 1);
}

bool NHTFlowCache::create_hash_key(Packet& pkt)
{
	if (pkt.ip_version != IP::v4 && pkt.ip_version != IP::v6) {
		return false;
	}

	m_flowKey = FlowKey{
		.srcIp = {pkt.src_ip, static_cast<IP>(pkt.ip_proto)},
		.dstIp = {pkt.dst_ip, static_cast<IP>(pkt.ip_proto)},
		.srcPort = pkt.src_port,
		.dstPort = pkt.dst_port,
		.l4Protocol = pkt.ip_proto
	};

	if (std::tie(m_flowKey.dstPort, m_flowKey.dstIp) < std::tie(m_flowKey.srcPort, m_flowKey.srcIp)) {
		std::swap(m_flowKey.srcPort, m_flowKey.dstPort);
		std::swap(m_flowKey.srcIp, m_flowKey.dstIp);
	}

	return true;
}

#ifdef FLOW_CACHE_STATS
void NHTFlowCache::print_report()
{
	float tmp = float(m_lookups) / m_hits;

	cout << "Hits: " << m_hits << endl;
	cout << "Empty: " << m_empty << endl;
	cout << "Not empty: " << m_not_empty << endl;
	cout << "Expired: " << m_expired << endl;
	cout << "Flushed: " << m_flushed << endl;
	cout << "Average Lookup:  " << tmp << endl;
	cout << "Variance Lookup: " << float(m_lookups2) / m_hits - tmp * tmp << endl;
}
#endif /* FLOW_CACHE_STATS */

void NHTFlowCache::set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir)
{
	telemetry::FileOps statsOps = {[this]() { return get_cache_telemetry(); }, nullptr};
	register_file(dir, "cache-stats", statsOps);

	if (m_enable_fragmentation_cache) {
		m_fragmentation_cache.set_telemetry_dir(dir);
	}
}

void NHTFlowCache::update_flow_record_stats(uint64_t packets_count)
{
	if (packets_count == 1) {
		m_flow_record_stats.packets_count_1++;
	} else if (packets_count >= 2 && packets_count <= 5) {
		m_flow_record_stats.packets_count_2_5++;
	} else if (packets_count >= 6 && packets_count <= 10) {
		m_flow_record_stats.packets_count_6_10++;
	} else if (packets_count >= 11 && packets_count <= 20) {
		m_flow_record_stats.packets_count_11_20++;
	} else if (packets_count >= 21 && packets_count <= 50) {
		m_flow_record_stats.packets_count_21_50++;
	} else {
		m_flow_record_stats.packets_count_51_plus++;
	}
}

void NHTFlowCache::update_flow_end_reason_stats(uint8_t reason)
{
	switch (static_cast<FlowEndReason>(reason)) {
	case FlowEndReason::FLOW_END_ACTIVE:
		m_flow_end_reason_stats.active_timeout++;
		break;
	case FlowEndReason::FLOW_END_INACTIVE:
		m_flow_end_reason_stats.inactive_timeout++;
		break;
	case FlowEndReason::FLOW_END_EOF:
		m_flow_end_reason_stats.end_of_flow++;
		break;
	case FlowEndReason::FLOW_END_NO_RES:
		m_flow_end_reason_stats.collision++;
		break;
	case FlowEndReason::FLOW_END_FORCED:
		m_flow_end_reason_stats.forced++;
		break;
	default:
		break;
	}
}

telemetry::Content NHTFlowCache::get_cache_telemetry()
{
	telemetry::Dict dict;

	dict["FlowEndReason:ActiveTimeout"] = m_flow_end_reason_stats.active_timeout;
	dict["FlowEndReason:InactiveTimeout"] = m_flow_end_reason_stats.inactive_timeout;
	dict["FlowEndReason:EndOfFlow"] = m_flow_end_reason_stats.end_of_flow;
	dict["FlowEndReason:Collision"] = m_flow_end_reason_stats.collision;
	dict["FlowEndReason:Forced"] = m_flow_end_reason_stats.forced;

	dict["FlowsInCache"] = m_flows_in_cache;
	dict["FlowCacheUsage"]
		= telemetry::ScalarWithUnit {double(m_flows_in_cache) / m_cache_size * 100, "%"};

	dict["FlowRecordStats:1packet"] = m_flow_record_stats.packets_count_1;
	dict["FlowRecordStats:2-5packets"] = m_flow_record_stats.packets_count_2_5;
	dict["FlowRecordStats:6-10packets"] = m_flow_record_stats.packets_count_6_10;
	dict["FlowRecordStats:11-20packets"] = m_flow_record_stats.packets_count_11_20;
	dict["FlowRecordStats:21-50packets"] = m_flow_record_stats.packets_count_21_50;
	dict["FlowRecordStats:51-plusPackets"] = m_flow_record_stats.packets_count_51_plus;

	dict["TotalExportedFlows"] = m_total_exported;

	return dict;
}

void NHTFlowCache::prefetch_export_expired() const
{
	for (decltype(m_timeout_idx) i = m_timeout_idx; i < m_timeout_idx + m_line_new_idx; i++) {
		//__builtin_prefetch(m_flow_table[i], 0, 1); TODO? 
	}
}

static const PluginRegistrar<NHTFlowCache, StoragePluginFactory>
	cacheRegistrar(cachePluginManifest);

} // namespace ipxp
