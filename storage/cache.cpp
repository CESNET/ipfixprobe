/**
 * \file cache.cpp
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

#include <cstdlib>
#include <iostream>
#include <cstring>
#include <ratio>
#include <sys/time.h>

#include <ipfixprobe/ring.h>
#include "cache.hpp"

#include <optional>
#include "cacheRowSpan.hpp"
#include "xxhash.h"

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("cache", [](){return new NHTFlowCache();});
   register_plugin(&rec);
}

OptionsParser * NHTFlowCache::get_parser() const
{
    return new CacheOptParser();
}

std::string NHTFlowCache::get_name() const noexcept
{
    return "cache";
}

NHTFlowCache::NHTFlowCache() :
   m_cache_size(0), m_line_size(0), m_line_mask(0), m_new_flow_insert_index(0),
   m_queue_size(0), m_active(0), m_inactive(0),
   m_split_biflow(false), m_enable_fragmentation_cache(true),
   m_fragmentation_cache(0, 0)
{
}

NHTFlowCache::~NHTFlowCache()
{
   close();
}

void NHTFlowCache::get_parser_options(CacheOptParser& parser) noexcept
{
    m_cache_size = parser.m_cache_size;
    m_line_size = parser.m_line_size;
    m_active = parser.m_active;
    m_inactive = parser.m_inactive;
    m_line_mask = (m_cache_size - 1) & ~(m_line_size - 1);
    m_new_flow_insert_index = m_line_size / 2;
    m_split_biflow = parser.m_split_biflow;
    m_enable_fragmentation_cache = parser.m_enable_fragmentation_cache;
#ifdef WITH_CTT
    m_ctt_controller.init(parser.m_dev, 0);
#endif /* WITH_CTT */
}

void NHTFlowCache::allocate_table()
{
    try {
        m_flow_table.resize(m_cache_size + m_queue_size);
        m_flows.resize(m_cache_size + m_queue_size);
        std::for_each(m_flow_table.begin(), m_flow_table.end(), [index = 0, this](FlowRecord*& flow) mutable  {
            flow = &m_flows[index++];
        });
    } catch (std::bad_alloc &e) {
        throw PluginError("not enough memory for flow cache allocation");
    }
}

void NHTFlowCache::init(const char *params)
{
   CacheOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   get_parser_options(parser);
   if (m_export_queue == nullptr) {
      throw PluginError("output queue must be set before init");
   }
   if (m_line_size > m_cache_size) {
      throw PluginError("flow cache line size must be greater or equal to cache size");
   }
   if (m_cache_size == 0) {
      throw PluginError("flow cache won't properly work with 0 records");
   }
   allocate_table();

   if (m_enable_fragmentation_cache) {
      try {
         m_fragmentation_cache = FragmentationCache(parser.m_frag_cache_size, parser.m_frag_cache_timeout);
      } catch (std::bad_alloc &e) {
         throw PluginError("not enough memory for fragment cache allocation");
      }
   }
}

void NHTFlowCache::close()
{
   m_flows.clear();
   m_flow_table.clear();
}

void NHTFlowCache::set_queue(ipx_ring_t *queue)
{
   m_export_queue = queue;
   m_queue_size = ipx_ring_size(queue);
}

void NHTFlowCache::export_flow(size_t flow_index)
{
   export_flow(flow_index, get_export_reason(m_flow_table[flow_index]->m_flow));
}

void NHTFlowCache::export_flow(size_t flow_index, int reason)
{
   /*if (m_flow_table[index]->m_flow.is_delayed) {
      return;
   }
   if (m_flow_table[index]->m_delayed_flow_waiting && !m_flow_table[index]->m_delayed_flow.is_delayed) {
      m_total_exported++;
      update_flow_end_reason_stats(m_flow_table[index]->m_delayed_flow.end_reason);
      update_flow_record_stats(
         m_flow_table[index]->m_delayed_flow.src_packets 
         + m_flow_table[index]->m_delayed_flow.dst_packets);
      ipx_ring_push(m_export_queue, &m_flow_table[index]->m_delayed_flow);
   }
   m_total_exported++;
   update_flow_end_reason_stats(m_flow_table[index]->m_flow.end_reason);
   update_flow_record_stats(
      m_flow_table[index]->m_flow.src_packets 
      + m_flow_table[index]->m_flow.dst_packets);
   m_flows_in_cache--;*/
   m_flow_table[flow_index]->m_flow.end_reason = reason;
   m_cache_stats.expired++;
   push_to_export_queue(flow_index);
   m_flow_table[flow_index]->erase();
}

void NHTFlowCache::push_to_export_queue(size_t flow_index) noexcept
{
   ipx_ring_push(m_export_queue, &m_flow_table[flow_index]->m_flow);
   std::swap(m_flow_table[flow_index], m_flow_table[m_cache_size + m_queue_index]);
   m_queue_index = (m_queue_index + 1) % m_queue_size;
}

void NHTFlowCache::finish()
{
   for (decltype(m_cache_size) i = 0; i < m_cache_size; i++) {
      if (!m_flow_table[i]->is_empty()) {
         plugins_pre_export(m_flow_table[i]->m_flow);
         //m_flow_table[i]->m_flow.end_reason = FLOW_END_FORCED;
         export_flow(i, FLOW_END_FORCED);
         //m_cache_stats.expired++;
      }
   }
}

void NHTFlowCache::flush(Packet &pkt, size_t flow_index, int status, bool source_flow)
{
   m_cache_stats.flushed++;

   if (status == ProcessPlugin::FlowAction::FLUSH_WITH_REINSERT) {
      //FlowRecord *flow = m_flow_table[flow_index];
      //export_flow(flow_index, FLOW_END_FORCED);
      push_to_export_queue(flow_index);
      //flow->m_flow.end_reason = FLOW_END_FORCED;
      //ipx_ring_push(m_export_queue, &flow->m_flow);
      //std::swap(m_flow_table[flow_index], m_flow_table[m_cache_size + m_queue_index]);
      //flow = m_flow_table[flow_index];

      m_flow_table[flow_index]->m_flow.remove_extensions();
      *m_flow_table[flow_index] = *m_flow_table[m_cache_size + m_queue_index];
      //m_queue_index = (m_queue_index + 1) % m_queue_size;

      m_flow_table[flow_index]->m_flow.m_exts = nullptr;
      m_flow_table[flow_index]->reuse(); // Clean counters, set time first to last
      m_flow_table[flow_index]->update(pkt, source_flow); // Set new counters from packet

      const size_t post_create_return_flags = plugins_post_create(m_flow_table[flow_index]->m_flow, pkt);
      if (post_create_return_flags & ProcessPlugin::FlowAction::FLUSH) {
         flush(pkt, flow_index, post_create_return_flags, source_flow);
      }
   } else {
      //m_flow_table[flow_index]->m_flow.end_reason = FLOW_END_FORCED;
      export_flow(flow_index, FLOW_END_FORCED);
   }
}

std::tuple<std::optional<size_t>, std::optional<size_t>, bool> NHTFlowCache::find_flow_index(const Packet& packet) noexcept
{
   if (!create_hash_key(packet)) {
      return {std::nullopt, std::nullopt, false};
   }

   const auto key_hasher = [](const auto& key)
   {
      return XXH64(&key, sizeof(key), 0);
   };

   const size_t direct_hash_value = std::visit(key_hasher, m_key);
   const size_t first_flow_in_raw = direct_hash_value & m_line_mask;
   const CacheRowSpan raw_span_direct(&m_flow_table[first_flow_in_raw], m_line_size);
   std::optional<size_t> flow_index = raw_span_direct.find_by_hash(direct_hash_value);
   if (flow_index.has_value()) {
      return {direct_hash_value, flow_index, true};
   }

   const size_t reversed_hash_value = std::visit(key_hasher, m_key_reversed);
   const size_t first_flow_in_raw_reversed = direct_hash_value & m_line_mask;
   const CacheRowSpan raw_span_reverse(&m_flow_table[first_flow_in_raw_reversed], m_line_size);
   flow_index = raw_span_reverse.find_by_hash(direct_hash_value);
   if (flow_index.has_value()) {
      return {reversed_hash_value, flow_index, false};
   }

   return {direct_hash_value, std::nullopt, false};
}

static bool isTcpConnectionRestart(const Packet& packet, const Flow& flow, bool source_to_destination) noexcept
{
   constexpr uint8_t TCP_FIN = 0x01;
   constexpr uint8_t TCP_RST = 0x04;
   constexpr uint8_t TCP_SYN = 0x02;
   const uint8_t flags = source_to_destination ? flow.src_tcp_flags : flow.dst_tcp_flags;
   return packet.tcp_flags & TCP_SYN && (flags & (TCP_FIN | TCP_RST));
}

bool NHTFlowCache::export_on_inactive_timeout(size_t flow_index, time_t ts) noexcept
{
   if (ts - m_flow_table[flow_index]->m_flow.time_last.tv_sec >= m_inactive) {
      plugins_pre_export(m_flow_table[flow_index]->m_flow);
      export_flow(flow_index);
      return true;
   }
   return false;
}

bool NHTFlowCache::export_on_active_timeout(size_t flow_index, time_t ts) noexcept
{
   if (ts - m_flow_table[flow_index]->m_flow.time_first.tv_sec >= m_active) {
      m_flow_table[flow_index]->m_flow.end_reason = FLOW_END_ACTIVE;
      plugins_pre_export(m_flow_table[flow_index]->m_flow);
      export_flow(flow_index);
      return true;
   }
   return false;
}

int NHTFlowCache::put_pkt(Packet &pkt)
{
   plugins_pre_create(pkt);

   if (m_enable_fragmentation_cache) {
      try_to_fill_ports_to_fragmented_packet(pkt);
   }

   auto [hash_value, flow_index, source_to_destination] = find_flow_index(pkt);
   const bool hash_created = hash_value.has_value();
   const bool flow_found = flow_index.has_value();
   if (!hash_created) {
      return 0;
   }
   const size_t row_begin = hash_value.value() & m_line_mask;
   CacheRowSpan row_span(&m_flow_table[row_begin], m_line_size);

   prefetch_export_expired();

   if (flow_found) {
      /* Existing flow record was found, put flow record at the first index of flow line. */
      m_cache_stats.lookups += (flow_index.value() - row_begin + 1);
      m_cache_stats.lookups2 += (flow_index.value() - row_begin + 1) * (flow_index.value() - row_begin + 1);
      m_cache_stats.hits++;

      row_span.advance_flow(flow_index.value());
   } else {
      /* Existing flow record was not found. Find free place in flow line. */
      const std::optional<size_t> empty_index = row_span.find_empty();
      const bool empty_found = empty_index.has_value();
      if (empty_found) {
         flow_index = empty_index.value() + row_begin;
         m_cache_stats.empty++;
      } else {
         row_span.advance_flow_to(m_line_size - 1, m_new_flow_insert_index);
         flow_index = row_begin + m_new_flow_insert_index;
         plugins_pre_export(m_flow_table[flow_index.value()]->m_flow);
         m_flow_table[flow_index.value()]->m_flow.end_reason = FLOW_END_NO_RES;
         export_flow(flow_index.value());
         m_cache_stats.expired++;
         m_cache_stats.not_empty++;
      }
   }

   pkt.source_pkt = source_to_destination;
   if (isTcpConnectionRestart(pkt, m_flow_table[flow_index.value()]->m_flow, source_to_destination)) {
      //m_flow_table[flow_index.value()]->m_flow.end_reason = FLOW_END_EOF;
      export_flow(flow_index.value(), FLOW_END_EOF);
      put_pkt(pkt);
      return 0;
   }

   if (m_flow_table[flow_index.value()]->is_empty()) {
      m_cache_stats.flows_in_cache++;
      m_flow_table[flow_index.value()]->create(pkt, hash_value.value());
      if (plugins_post_create(m_flow_table[flow_index.value()]->m_flow, pkt) & ProcessPlugin::FlowAction::FLUSH) {
         export_flow(flow_index.value());
         m_cache_stats.flushed++;
      }
      export_expired(pkt.ts.tv_sec);
      return 0;
   }
   /* Check if flow record is expired (inactive timeout). */
   if (export_on_inactive_timeout(flow_index.value(), pkt.ts.tv_sec)) {
      return put_pkt(pkt);
   }

   if (export_on_active_timeout(flow_index.value(), pkt.ts.tv_sec)) {
      return put_pkt(pkt);
   }

   const size_t pre_update_return_flags = plugins_pre_update(m_flow_table[flow_index.value()]->m_flow, pkt);
   if (pre_update_return_flags & ProcessPlugin::FlowAction::FLUSH) {
      flush(pkt, flow_index.value(), pre_update_return_flags, source_to_destination);
      return 0;
   }
   m_flow_table[flow_index.value()]->update(pkt, source_to_destination);
   const size_t post_update_return_flags = plugins_post_update(m_flow_table[flow_index.value()]->m_flow, pkt);

   if (post_update_return_flags & ProcessPlugin::FlowAction::FLUSH) {
      flush(pkt, flow_index.value(), post_update_return_flags, source_to_destination);
      return 0;
   }

   export_expired(pkt.ts.tv_sec);
   return 0;
}

void NHTFlowCache::try_to_fill_ports_to_fragmented_packet(Packet& packet)
{
   m_fragmentation_cache.process_packet(packet);
}

uint8_t NHTFlowCache::get_export_reason(const Flow& flow)
{
   constexpr uint8_t TCP_FIN = 0x01;
   constexpr uint8_t TCP_RST = 0x04;
   if ((flow.src_tcp_flags | flow.dst_tcp_flags) & (TCP_FIN | TCP_RST)) {
      // When FIN or RST is set, TCP connection ended naturally
      return FLOW_END_EOF;
   } else {
      return FLOW_END_INACTIVE;
   }
}

void NHTFlowCache::export_expired(time_t ts)
{
   for (decltype(m_last_exported_on_timeout_index) i = m_last_exported_on_timeout_index; i < m_last_exported_on_timeout_index + m_new_flow_insert_index; i++) {
      if (!m_flow_table[i]->is_empty() && ts - m_flow_table[i]->m_flow.time_last.tv_sec >= m_inactive) {
         m_flow_table[i]->m_flow.end_reason = get_export_reason(m_flow_table[i]->m_flow);
         plugins_pre_export(m_flow_table[i]->m_flow);
         export_flow(i);
         /*if (!m_flow_table[i]->is_empty() && m_flow_table[i]->m_flow.is_delayed && m_flow_table[i]->m_flow.delay_time >= ts) {
            m_flow_table[i]->m_flow.is_delayed = false;
            plugins_pre_export(m_flow_table[i]->m_flow);
            export_flow(i);
         }
         if(!m_flow_table[i]->is_empty() && m_flow_table[i]->m_delayed_flow_waiting && m_flow_table[i]->m_delayed_flow.delay_time >= ts) {
            m_flow_table[i]->m_delayed_flow_waiting = false;
            plugins_pre_export(m_flow_table[i]->m_delayed_flow);
            export_flow(i);
         }*/
         m_cache_stats.expired++;
      }
   }

   m_last_exported_on_timeout_index = (m_last_exported_on_timeout_index + m_new_flow_insert_index) & (m_cache_size - 1);
}

template<typename Type, size_t ArraySize>
static std::array<uint8_t, ArraySize> pointerToByteArray(const Type* pointer) noexcept
{
   std::array<uint8_t, ArraySize> res;
   std::copy_n(reinterpret_cast<const uint8_t*>(pointer), ArraySize, res.begin());
   return res;
}

template<typename ScalarType>
static const uint8_t* scalarToArrayEnd(const ScalarType& scalar) noexcept
{
    return scalarToArrayBegin(scalar) + sizeof(scalar);
}

bool NHTFlowCache::create_hash_key(const Packet& packet)
{
   if (packet.ip_version == IP::v4) {
      m_key = FlowKeyv4{ packet.src_port, packet.dst_port, packet.ip_proto, IP::v4,
         pointerToByteArray<uint32_t, sizeof(uint32_t)>(&packet.src_ip.v4),
         pointerToByteArray<uint32_t, sizeof(uint32_t)>(&packet.dst_ip.v4),
         static_cast<uint16_t>(packet.vlan_id)};
      m_key_reversed = FlowKeyv4{ packet.dst_port, packet.src_port, packet.ip_proto, IP::v4,
         pointerToByteArray<uint32_t, sizeof(uint32_t)>(&packet.dst_ip.v4),
         pointerToByteArray<uint32_t, sizeof(uint32_t)>(&packet.src_ip.v4),
         static_cast<uint16_t>(packet.vlan_id)};
      return true;
   }
   if (packet.ip_version == IP::v6) {
      m_key = FlowKeyv6{ packet.src_port, packet.dst_port, packet.ip_proto, IP::v6,
         pointerToByteArray<uint8_t, sizeof(packet.src_ip.v6)>(packet.src_ip.v6),
         pointerToByteArray<uint8_t, sizeof(packet.dst_ip.v6)>(packet.dst_ip.v6),
         static_cast<uint16_t>(packet.vlan_id)};
      m_key_reversed = FlowKeyv6{ packet.dst_port, packet.src_port, packet.ip_proto, IP::v6,
         pointerToByteArray<uint8_t, sizeof(packet.dst_ip.v6)>(packet.dst_ip.v6),
         pointerToByteArray<uint8_t, sizeof(packet.src_ip.v6)>(packet.src_ip.v6),
         static_cast<uint16_t>(packet.vlan_id)};
      return true;
   }
   return false;
}

void NHTFlowCache::print_report()
{
   /*1float tmp = float(m_cache_stats.lookups) / m_cache_stats.hits;

   cout << "Hits: " << m_cache_stats.hits << endl;
   cout << "Empty: " << m_cache_stats.empty << endl;
   cout << "Not empty: " << m_cache_stats.not_empty << endl;
   cout << "Expired: " << m_cache_stats.expired << endl;
   cout << "Flushed: " << m_cache_stats.flushed << endl;
   cout << "Average Lookup:  " << tmp << endl;
   cout << "Variance Lookup: " << float(m_cache_stats.lookups2) / m_cache_stats.hits - tmp * tmp << endl;*/
}

void NHTFlowCache::set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir)
{
   telemetry::FileOps statsOps = {[=]() { return get_cache_telemetry(); }, nullptr};
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
   switch (reason) {
   case FLOW_END_ACTIVE:
      m_flow_end_reason_stats.active_timeout++;
      break;
   case FLOW_END_INACTIVE:
      m_flow_end_reason_stats.inactive_timeout++;
      break;
   case FLOW_END_EOF:
      m_flow_end_reason_stats.end_of_flow++;
      break;
   case FLOW_END_NO_RES:
      m_flow_end_reason_stats.collision++;
      break;
   case FLOW_END_FORCED:
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

   dict["FlowsInCache"] = m_cache_stats.flows_in_cache;
   dict["FlowCacheUsage"] = telemetry::ScalarWithUnit {double(m_cache_stats.flows_in_cache) / m_cache_size * 100, "%"};

   dict["FlowRecordStats:1packet"] = m_flow_record_stats.packets_count_1;
   dict["FlowRecordStats:2-5packets"] = m_flow_record_stats.packets_count_2_5;
   dict["FlowRecordStats:6-10packets"] = m_flow_record_stats.packets_count_6_10;
   dict["FlowRecordStats:11-20packets"] = m_flow_record_stats.packets_count_11_20;
   dict["FlowRecordStats:21-50packets"] = m_flow_record_stats.packets_count_21_50;
   dict["FlowRecordStats:51-plusPackets"] = m_flow_record_stats.packets_count_51_plus;

   dict["TotalExportedFlows"] = m_cache_stats.total_exported;

   return dict;
}

void NHTFlowCache::prefetch_export_expired() const
{
   for (decltype(m_last_exported_on_timeout_index) i = m_last_exported_on_timeout_index; i < m_last_exported_on_timeout_index + m_new_flow_insert_index; i++) {
      __builtin_prefetch(m_flow_table[i], 0, 1);
   }
}

}