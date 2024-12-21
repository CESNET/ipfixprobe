/**
 * \file cache.hpp
 * \brief "NewHashTable" flow cache
 * \author Martin Zadnik <zadnik@cesnet.cz>
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *
 *
 */
#ifndef IPXP_STORAGE_CACHE_HPP
#define IPXP_STORAGE_CACHE_HPP

#include <bits/types/struct_timeval.h>
#include <chrono>
#include <ctime>
#include <string>

#include <ipfixprobe/storage.hpp>
//#include <ipfixprobe/options.hpp>
#include <optional>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/telemetry-utils.hpp>

#include "fragmentationCache/fragmentationCache.hpp"

#include "cacheOptParser.hpp"
#include "flowKey.tpp"
#include "flowRecord.hpp"
#include "cttController.hpp"


namespace ipxp {



/*struct __attribute__((packed)) flow_key_v4_t {
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
};*/

//#define MAX_KEY_LENGTH (std::max<size_t>(sizeof(flow_key_v4_t), sizeof(flow_key_v6_t)))


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

struct FlowCacheStats{
   uint64_t empty;
   uint64_t not_empty;
   uint64_t hits;
   uint64_t expired;
   uint64_t flushed;
   uint64_t lookups;
   uint64_t lookups2;
   uint64_t flows_in_cache;
   uint64_t total_exported;
};

class NHTFlowCache : TelemetryUtils, public StoragePlugin
{
public:
   NHTFlowCache();
   ~NHTFlowCache() override;
   void init(const char* params) override;
   void close() override;
   void set_queue(ipx_ring_t* queue) override;
   OptionsParser * get_parser() const override;
   std::string get_name() const noexcept override;

   int put_pkt(Packet& pkt) override;
   void export_expired(time_t ts) override;

   /**
     * @brief Set and configure the telemetry directory where cache stats will be stored.
     */
   void set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir) override;

private:
   uint32_t m_cache_size;
   uint32_t m_line_size;
   uint32_t m_line_mask;
   uint32_t m_new_flow_insert_index;
   uint32_t m_queue_size;
   uint32_t m_queue_index{0};
   uint32_t m_last_exported_on_timeout_index{0};

   uint32_t m_active;
   uint32_t m_inactive;
   bool m_split_biflow;
   bool m_enable_fragmentation_cache;
   //uint8_t m_keylen;
   //std::array<uint8_t, std::max(sizeof(FlowKeyv4), sizeof(FlowKeyv6))> m_key_hash_buffer;
   std::variant<FlowKeyv4, FlowKeyv6> m_key;
   std::variant<FlowKeyv4, FlowKeyv6> m_key_reversed;
   //std::array<uint8_t, std::max(sizeof(FlowKeyv4), sizeof(FlowKeyv6))> m_key_reversed_hash_buffer;
   std::vector<FlowRecord*> m_flow_table;
   std::vector<FlowRecord> m_flows;

   FragmentationCache m_fragmentation_cache;
   FlowEndReasonStats m_flow_end_reason_stats = {};
   FlowRecordStats m_flow_record_stats = {};
   FlowCacheStats m_cache_stats = {};
#ifdef WITH_CTT
   CttController m_ctt_controller;
#endif /* WITH_CTT */


   void try_to_fill_ports_to_fragmented_packet(Packet& packet);
   void flush(Packet &pkt, size_t flow_index, int ret, bool source_flow);
   bool create_hash_key(const Packet &packet);
   static uint8_t get_export_reason(const Flow &flow);
   void finish();
   void allocate_table();
   void update_flow_end_reason_stats(uint8_t reason);
   void update_flow_record_stats(uint64_t packets_count);
   telemetry::Content get_cache_telemetry();
   void prefetch_export_expired() const;
   void get_parser_options(CacheOptParser& parser) noexcept;
   void push_to_export_queue(size_t flow_index) noexcept;
   std::tuple<std::optional<size_t>, std::optional<size_t>, bool> find_flow_index(const Packet& packet) noexcept;
   bool export_on_inactive_timeout(size_t flow_index, time_t ts) noexcept;
   bool export_on_active_timeout(size_t flow_index, time_t ts) noexcept;
   void export_flow(size_t flow_index, int reason);
   void export_flow(size_t flow_index);
   void print_report();
};

}
#endif /* IPXP_STORAGE_CACHE_HPP */