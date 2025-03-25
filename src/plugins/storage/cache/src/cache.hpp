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

#pragma once

#include "fragmentationCache/fragmentationCache.hpp"

#include <string>

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/storagePlugin.hpp>
#include <ipfixprobe/telemetry-utils.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

struct __attribute__((packed)) flow_key_v4_t {
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
	uint8_t ip_version;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t vlan_id;
};

struct __attribute__((packed)) flow_key_v6_t {
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
	uint8_t ip_version;
	uint8_t src_ip[16];
	uint8_t dst_ip[16];
	uint16_t vlan_id;
};

#define MAX_KEY_LENGTH (max<size_t>(sizeof(flow_key_v4_t), sizeof(flow_key_v6_t)))

#ifdef IPXP_FLOW_CACHE_SIZE
static const uint32_t DEFAULT_FLOW_CACHE_SIZE = IPXP_FLOW_CACHE_SIZE;
#else
static const uint32_t DEFAULT_FLOW_CACHE_SIZE = 17; // 131072 records total
#endif /* IPXP_FLOW_CACHE_SIZE */

#ifdef IPXP_FLOW_LINE_SIZE
static const uint32_t DEFAULT_FLOW_LINE_SIZE = IPXP_FLOW_LINE_SIZE;
#else
static const uint32_t DEFAULT_FLOW_LINE_SIZE = 4; // 16 records per line
#endif /* IPXP_FLOW_LINE_SIZE */

static const uint32_t DEFAULT_INACTIVE_TIMEOUT = 30;
static const uint32_t DEFAULT_ACTIVE_TIMEOUT = 300;

static_assert(
	std::is_unsigned<decltype(DEFAULT_FLOW_CACHE_SIZE)>(),
	"Static checks of default cache sizes won't properly work without unsigned type.");
static_assert(
	bitcount<decltype(DEFAULT_FLOW_CACHE_SIZE)>(-1) > DEFAULT_FLOW_CACHE_SIZE,
	"Flow cache size is too big to fit in variable!");
static_assert(
	bitcount<decltype(DEFAULT_FLOW_LINE_SIZE)>(-1) > DEFAULT_FLOW_LINE_SIZE,
	"Flow cache line size is too big to fit in variable!");

static_assert(DEFAULT_FLOW_LINE_SIZE >= 1, "Flow cache line size must be at least 1!");
static_assert(
	DEFAULT_FLOW_CACHE_SIZE >= DEFAULT_FLOW_LINE_SIZE,
	"Flow cache size must be at least cache line size!");

class CacheOptParser : public OptionsParser {
public:
	uint32_t m_cache_size;
	uint32_t m_line_size;
	uint32_t m_active;
	uint32_t m_inactive;
	bool m_split_biflow;
	bool m_enable_fragmentation_cache;
	std::size_t m_frag_cache_size;
	time_t m_frag_cache_timeout;

	CacheOptParser()
		: OptionsParser("cache", "Storage plugin implemented as a hash table")
		, m_cache_size(1 << DEFAULT_FLOW_CACHE_SIZE)
		, m_line_size(1 << DEFAULT_FLOW_LINE_SIZE)
		, m_active(DEFAULT_ACTIVE_TIMEOUT)
		, m_inactive(DEFAULT_INACTIVE_TIMEOUT)
		, m_split_biflow(false)
		, m_enable_fragmentation_cache(true)
		, m_frag_cache_size(10007)
		, // Prime for better distribution in hash table
		m_frag_cache_timeout(3)
	{
		register_option(
			"s",
			"size",
			"EXPONENT",
			"Cache size exponent to the power of two",
			[this](const char* arg) {
				try {
					unsigned exp = str2num<decltype(exp)>(arg);
					if (exp < 4 || exp > 30) {
						throw PluginError("Flow cache size must be between 4 and 30");
					}
					m_cache_size = static_cast<uint32_t>(1) << exp;
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"l",
			"line",
			"EXPONENT",
			"Cache line size exponent to the power of two",
			[this](const char* arg) {
				try {
					m_line_size = static_cast<uint32_t>(1) << str2num<decltype(m_line_size)>(arg);
					if (m_line_size < 1) {
						throw PluginError("Flow cache line size must be at least 1");
					}
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"a",
			"active",
			"TIME",
			"Active timeout in seconds",
			[this](const char* arg) {
				try {
					m_active = str2num<decltype(m_active)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"i",
			"inactive",
			"TIME",
			"Inactive timeout in seconds",
			[this](const char* arg) {
				try {
					m_inactive = str2num<decltype(m_inactive)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"S",
			"split",
			"",
			"Split biflows into uniflows",
			[this](const char* arg) {
				(void) arg;
				m_split_biflow = true;
				return true;
			},
			OptionFlags::NoArgument);
		register_option(
			"fe",
			"frag-enable",
			"true|false",
			"Enable/disable fragmentation cache. Enabled (true) by default.",
			[this](const char* arg) {
				if (strcmp(arg, "true") == 0) {
					m_enable_fragmentation_cache = true;
				} else if (strcmp(arg, "false") == 0) {
					m_enable_fragmentation_cache = false;
				} else {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"fs",
			"frag-size",
			"size",
			"Size of fragmentation cache, must be at least 1. Default value is 10007.",
			[this](const char* arg) {
				try {
					m_frag_cache_size = str2num<decltype(m_frag_cache_size)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return m_frag_cache_size > 0;
			});
		register_option(
			"ft",
			"frag-timeout",
			"TIME",
			"Timeout of fragments in fragmentation cache in seconds. Default value is 3.",
			[this](const char* arg) {
				try {
					m_frag_cache_timeout = str2num<decltype(m_frag_cache_timeout)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			});
	}
};

class alignas(64) FlowRecord {
	uint64_t m_hash;

public:
	Flow m_flow;

	FlowRecord();
	~FlowRecord();

	void erase();
	void reuse();

	inline bool is_empty() const;
	inline bool belongs(uint64_t pkt_hash) const;
	void create(const Packet& pkt, uint64_t pkt_hash);
	void update(const Packet& pkt, bool src);
};

struct FlowEndReasonStats {
	uint64_t active_timeout;
	uint64_t inactive_timeout;
	uint64_t end_of_flow;
	uint64_t collision;
	uint64_t forced;
};

struct FlowRecordStats {
	uint64_t packets_count_1;
	uint64_t packets_count_2_5;
	uint64_t packets_count_6_10;
	uint64_t packets_count_11_20;
	uint64_t packets_count_21_50;
	uint64_t packets_count_51_plus;
};

class NHTFlowCache
	: TelemetryUtils
	, public StoragePlugin {
public:
	NHTFlowCache(const std::string& params, ipx_ring_t* queue);
	~NHTFlowCache();
	void init(const char* params);
	void close();
	void set_queue(ipx_ring_t* queue);
	OptionsParser* get_parser() const { return new CacheOptParser(); }
	std::string get_name() const { return "cache"; }

	int put_pkt(Packet& pkt);
	void export_expired(time_t ts);

	/**
	 * @brief Set and configure the telemetry directory where cache stats will be stored.
	 */
	void set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir) override;

private:
	uint32_t m_cache_size;
	uint32_t m_line_size;
	uint32_t m_line_mask;
	uint32_t m_line_new_idx;
	uint32_t m_qsize;
	uint32_t m_qidx;
	uint32_t m_timeout_idx;
	uint64_t m_flows_in_cache = 0;
	uint64_t m_total_exported = 0;
#ifdef FLOW_CACHE_STATS
	uint64_t m_empty;
	uint64_t m_not_empty;
	uint64_t m_hits;
	uint64_t m_expired;
	uint64_t m_flushed;
	uint64_t m_lookups;
	uint64_t m_lookups2;
#endif /* FLOW_CACHE_STATS */
	uint32_t m_active;
	uint32_t m_inactive;
	bool m_split_biflow;
	bool m_enable_fragmentation_cache;
	uint8_t m_keylen;
	char m_key[MAX_KEY_LENGTH];
	char m_key_inv[MAX_KEY_LENGTH];
	FlowRecord** m_flow_table;
	FlowRecord* m_flow_records;

	FragmentationCache m_fragmentation_cache;
	FlowEndReasonStats m_flow_end_reason_stats = {};
	FlowRecordStats m_flow_record_stats = {};

	void try_to_fill_ports_to_fragmented_packet(Packet& packet);
	void flush(Packet& pkt, size_t flow_index, int ret, bool source_flow);
	bool create_hash_key(Packet& pkt);
	void export_flow(size_t index);
	static uint8_t get_export_reason(Flow& flow);
	void finish();

	void update_flow_end_reason_stats(uint8_t reason);
	void update_flow_record_stats(uint64_t packets_count);
	telemetry::Content get_cache_telemetry();
	void prefetch_export_expired() const;

#ifdef FLOW_CACHE_STATS
	void print_report();
#endif /* FLOW_CACHE_STATS */
};

} // namespace ipxp
