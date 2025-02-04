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
#include "cache.hpp"

#include <ipfixprobe/ring.h>
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <ratio>
#include <sys/time.h>
#include <optional>

#include "xxhash.h"
#include "fragmentationCache/timevalUtils.hpp"
#include "cacheRowSpan.hpp"

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
   NHTFlowCache::close();
   print_report();
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
   m_flow_table[flow_index]->m_flow.end_reason = reason;
   update_flow_record_stats(m_flow_table[flow_index]->m_flow.src_packets + m_flow_table[flow_index]->m_flow.dst_packets);
   update_flow_end_reason_stats(m_flow_table[flow_index]->m_flow.end_reason);
   m_cache_stats.exported++;
   push_to_export_queue(flow_index);
   m_flow_table[flow_index]->erase();
   m_cache_stats.flows_in_cache--;
   m_cache_stats.total_exported++;
}

void NHTFlowCache::push_to_export_queue(size_t flow_index) noexcept
{
   ipx_ring_push(m_export_queue, &m_flow_table[flow_index]->m_flow);
   std::swap(m_flow_table[flow_index], m_flow_table[m_cache_size + m_queue_index]);
   m_queue_index = (m_queue_index + 1) % m_queue_size;
}

void NHTFlowCache::finish()
{
   /*auto it = std::find_if(m_hashes_in_ctt.begin(), m_hashes_in_ctt.end(), [](const auto& pair) {
      return pair.second <= 0;
   });*/
   for (decltype(m_cache_size) i = 0; i < m_cache_size; i++) {
      if (!m_flow_table[i]->is_empty()) {
#ifdef WITH_CTT
         if (m_flow_table[i]->is_in_ctt && !m_flow_table[i]->is_waiting_for_export) {
            send_export_request_to_ctt(m_flow_table[i]->m_flow.flow_hash_ctt);
         }
#endif /* WITH_CTT */
         plugins_pre_export(m_flow_table[i]->m_flow);
         export_flow(i, FLOW_END_FORCED);
      }
   }
   /*if (m_hashes_in_ctt.size() > 0){
      throw "bad CTT size";
   }
   std::cout << "CTT hash collisions: " << m_ctt_hash_collision << std::endl;*/
}

void NHTFlowCache::flush(Packet &pkt, size_t flow_index, int return_flags)
{
   m_cache_stats.flushed++;

   if (return_flags == ProcessPlugin::FlowAction::FLUSH_WITH_REINSERT) {
#ifdef WITH_CTT
      if (m_flow_table[flow_index]->is_in_ctt && !m_flow_table[flow_index]->is_waiting_for_export) {
         m_flow_table[flow_index]->is_waiting_for_export = true;
         send_export_request_to_ctt(m_flow_table[flow_index]->m_flow.flow_hash_ctt);
      }
#endif /* WITH_CTT */
      push_to_export_queue(flow_index);
      m_flow_table[flow_index]->m_flow.remove_extensions();
      *m_flow_table[flow_index] = *m_flow_table[m_cache_size + m_queue_index];
      m_flow_table[flow_index]->m_flow.m_exts = nullptr;
      m_flow_table[flow_index]->reuse(); // Clean counters, set time first to last
      m_flow_table[flow_index]->update(pkt); // Set new counters from packet

      const size_t post_create_return_flags = plugins_post_create(m_flow_table[flow_index]->m_flow, pkt);
      if (post_create_return_flags & ProcessPlugin::FlowAction::FLUSH) {
         flush(pkt, flow_index, post_create_return_flags);
      }
      return;
   }
   try_to_export(flow_index, false, pkt.ts, FLOW_END_FORCED);
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
      return {direct_hash_value, flow_index.value(), true};
   }

   const size_t reversed_hash_value = std::visit(key_hasher, m_key_reversed);
   const size_t first_flow_in_raw_reversed = reversed_hash_value & m_line_mask;
   const CacheRowSpan raw_span_reverse(&m_flow_table[first_flow_in_raw_reversed], m_line_size);
   flow_index = raw_span_reverse.find_by_hash(reversed_hash_value);
   if (flow_index.has_value()) {
      return {reversed_hash_value, flow_index.value(), false};
   }

   return {direct_hash_value, std::nullopt, true};
}

static bool is_tcp_connection_restart(const Packet& packet, const Flow& flow) noexcept
{
   constexpr uint8_t TCP_FIN = 0x01;
   constexpr uint8_t TCP_RST = 0x04;
   constexpr uint8_t TCP_SYN = 0x02;
   const uint8_t flags = packet.source_pkt ? flow.src_tcp_flags : flow.dst_tcp_flags;
   return packet.tcp_flags & TCP_SYN && (flags & (TCP_FIN | TCP_RST));
}

bool NHTFlowCache::try_to_export_on_inactive_timeout(size_t flow_index, const timeval& now) noexcept
{
   if (!m_flow_table[flow_index]->is_empty() && now.tv_sec - m_flow_table[flow_index]->m_flow.time_last.tv_sec >= m_inactive) {
      return try_to_export(flow_index, false, now);
   }
   return false;
}

bool NHTFlowCache::needs_to_be_offloaded(size_t flow_index) const noexcept
{
   return only_metadata_required(m_flow_table[flow_index]->m_flow) && m_flow_table[flow_index]->m_flow.src_packets + m_flow_table[flow_index]->m_flow.dst_packets > 30;
}


void NHTFlowCache::create_record(const Packet& packet, size_t flow_index, size_t hash_value) noexcept
{
   m_cache_stats.flows_in_cache++;
   m_flow_table[flow_index]->create(packet, hash_value);
   const size_t post_create_return_flags = plugins_post_create(m_flow_table[flow_index]->m_flow, packet);
   if (post_create_return_flags & ProcessPlugin::FlowAction::FLUSH) {
      export_flow(flow_index);
      m_cache_stats.flushed++;
      return;
   }
#ifdef WITH_CTT
   // if metadata are valid, add flow hash ctt to the flow record
   if (!packet.cttmeta_valid) {
      return;
   }
   m_flow_table[flow_index]->m_flow.flow_hash_ctt = packet.cttmeta.flow_hash;
   if (needs_to_be_offloaded(flow_index)) {
      /*m_hashes_in_ctt[m_flow_table[flow_index]->m_flow.flow_hash_ctt]++;
      if (m_hashes_in_ctt[m_flow_table[flow_index]->m_flow.flow_hash_ctt] >= 2) {
         m_ctt_hash_collision++;
         std::vector<FlowRecord*> filtered;

         std::copy_if(m_flow_table.begin(), m_flow_table.end(), std::back_inserter(filtered),
                      [&](FlowRecord* flow) { return flow->m_flow.flow_hash_ctt == m_flow_table[flow_index]->m_flow.flow_hash_ctt; });
         filtered.size();
      }
      auto x = m_hashes_in_ctt[m_flow_table[flow_index]->m_flow.flow_hash_ctt];*/
      m_ctt_controller->create_record(m_flow_table[flow_index]->m_flow.flow_hash_ctt, m_flow_table[flow_index]->m_flow.time_first);
      m_cache_stats.ctt_offloaded++;
      m_flow_table[flow_index]->is_in_ctt = true;
   }
#endif /* WITH_CTT */
}

#ifdef WITH_CTT
void NHTFlowCache::try_to_add_flow_to_ctt(size_t flow_index) noexcept
{
   if (m_flow_table[flow_index]->is_in_ctt || m_flow_table[flow_index]->m_flow.flow_hash_ctt == 0) {
      return;
   }
   if (needs_to_be_offloaded(flow_index)) {
      /*m_hashes_in_ctt[m_flow_table[flow_index]->m_flow.flow_hash_ctt]++;
      auto x = m_hashes_in_ctt[m_flow_table[flow_index]->m_flow.flow_hash_ctt];
      if (m_hashes_in_ctt[m_flow_table[flow_index]->m_flow.flow_hash_ctt] >= 2) {
         m_ctt_hash_collision++;
         std::vector<FlowRecord*> filtered;

         std::copy_if(m_flow_table.begin(), m_flow_table.end(), std::back_inserter(filtered),
                      [&](FlowRecord* flow) { return flow->m_flow.flow_hash_ctt == m_flow_table[flow_index]->m_flow.flow_hash_ctt; });
         filtered.size();
      }*/
      m_ctt_controller->create_record(m_flow_table[flow_index]->m_flow.flow_hash_ctt, m_flow_table[flow_index]->m_flow.time_first);
      m_cache_stats.ctt_offloaded++;
      m_flow_table[flow_index]->is_in_ctt = true;
   }
}
#endif /* WITH_CTT */

int NHTFlowCache::process_flow(Packet& packet, size_t flow_index, bool flow_is_waiting_for_export) noexcept
{
   if (is_tcp_connection_restart(packet, m_flow_table[flow_index]->m_flow) && !flow_is_waiting_for_export) {
      if (try_to_export(flow_index, false, packet.ts, FLOW_END_EOF)) {
         put_pkt(packet);
         return 0;
      }
   }

   /* Check if flow record is expired (inactive timeout). */
   if (!flow_is_waiting_for_export
         && try_to_export_on_inactive_timeout(flow_index, packet.ts)) {
      return put_pkt(packet);
   }

   if (!flow_is_waiting_for_export
         && try_to_export_on_active_timeout(flow_index, packet.ts)) {
      return put_pkt(packet);
   }

   const size_t pre_update_return_flags = plugins_pre_update(m_flow_table[flow_index]->m_flow, packet);
   if ((pre_update_return_flags & ProcessPlugin::FlowAction::FLUSH)
      && !flow_is_waiting_for_export) {
      flush(packet, flow_index, pre_update_return_flags);
      return 0;
   }

   m_flow_table[flow_index]->update(packet);
#ifdef WITH_CTT
   try_to_add_flow_to_ctt(flow_index);
#endif /* WITH_CTT */
   const size_t post_update_return_flags = plugins_post_update(m_flow_table[flow_index]->m_flow, packet);
   if ((post_update_return_flags & ProcessPlugin::FlowAction::FLUSH)
         && !flow_is_waiting_for_export) {
      flush(packet, flow_index, post_update_return_flags);
      return 0;
   }

   export_expired(packet.ts);
   return 0;
}
#ifdef WITH_CTT
bool NHTFlowCache::try_to_export_delayed_flow(const Packet& packet, size_t flow_index) noexcept
{
   if (!m_flow_table[flow_index]->is_in_ctt) {
      return false;
   }
   if (m_flow_table[flow_index]->is_waiting_for_export &&
      ((packet.cttmeta_valid && !packet.cttmeta.ctt_rec_matched) || packet.ts > m_flow_table[flow_index]->export_time)) {
      plugins_pre_export(m_flow_table[flow_index]->m_flow);
      export_flow(flow_index);
      return false;
   }
   return m_flow_table[flow_index]->is_waiting_for_export;
}
#endif /* WITH_CTT */

bool NHTFlowCache::try_to_export(size_t flow_index, bool call_pre_export, const timeval& now) noexcept
{
   return try_to_export(flow_index, call_pre_export, now, get_export_reason(m_flow_table[flow_index]->m_flow));
}

#ifdef WITH_CTT
void NHTFlowCache::send_export_request_to_ctt(size_t ctt_flow_hash) noexcept
{
   /*if (--m_hashes_in_ctt[ctt_flow_hash] < 0)
   {
      throw "missing hash in send_export_request_to_ctt!";
   }
   if (m_hashes_in_ctt[ctt_flow_hash] == 0) {
      m_hashes_in_ctt.erase(ctt_flow_hash);
   }*/
   m_ctt_controller->export_record(ctt_flow_hash);
}
#endif /* WITH_CTT */

bool NHTFlowCache::try_to_export(size_t flow_index, bool call_pre_export, const timeval& now, int reason) noexcept
{
#ifdef WITH_CTT
   if (m_flow_table[flow_index]->is_in_ctt) {
      if (!m_flow_table[flow_index]->is_waiting_for_export) {
         m_flow_table[flow_index]->is_waiting_for_export = true;
         send_export_request_to_ctt(m_flow_table[flow_index]->m_flow.flow_hash_ctt);
         m_flow_table[flow_index]->export_time = {now.tv_sec + 1, now.tv_usec};
         return false;
      }
      if (m_flow_table[flow_index]->export_time > now) {
         return false;
      }
      m_flow_table[flow_index]->is_waiting_for_export = false;
   }
#endif /* WITH_CTT */
   if (call_pre_export) {
      plugins_pre_export(m_flow_table[flow_index]->m_flow);
   }
   export_flow(flow_index, reason);
   return true;
}

int NHTFlowCache::put_pkt(Packet &pkt)
{
   plugins_pre_create(pkt);

   if (m_enable_fragmentation_cache) {
      try_to_fill_ports_to_fragmented_packet(pkt);
   }

   prefetch_export_expired();

   auto [hash_value, flow_index, source_to_destination] = find_flow_index(pkt);
   pkt.source_pkt = source_to_destination;
   const bool hash_created = hash_value.has_value();
   const bool flow_found = flow_index.has_value();
   if (!hash_created) {
      return 0;
   }
   const size_t row_begin = hash_value.value() & m_line_mask;
   CacheRowSpan row_span(&m_flow_table[row_begin], m_line_size);

#ifdef WITH_CTT
   const bool flow_is_waiting_for_export = flow_found && try_to_export_delayed_flow(pkt, flow_index.value() + row_begin);
#else
   constexpr bool flow_is_waiting_for_export = false;
#endif /* WITH_CTT */

   if (flow_found && !m_flow_table[flow_index.value() + row_begin]->is_empty()) {
      /* Existing flow record was found, put flow record at the first index of flow line. */
      m_cache_stats.lookups += flow_index.value() + 1;
      m_cache_stats.lookups2 += (flow_index.value() + 1) * (flow_index.value() + 1);
      m_cache_stats.hits++;

      row_span.advance_flow(flow_index.value());
      flow_index = row_begin;
      return process_flow(pkt, flow_index.value(), flow_is_waiting_for_export);
   }
   /* Existing flow record was not found. Find free place in flow line. */
   const std::optional<size_t> empty_index = flow_found && m_flow_table[flow_index.value() + row_begin]->is_empty()
                                                                                          ? flow_index.value()
                                                                                          : row_span.find_empty();
   const bool empty_found = empty_index.has_value();
   if (empty_found) {
      flow_index = empty_index.value() + row_begin;
      m_cache_stats.empty++;
   } else {
#ifdef WITH_CTT
      const size_t victim_index = row_span.find_victim(pkt.ts);
#else
      const size_t victim_index = m_line_size - 1;
#endif /* WITH_CTT */
      row_span.advance_flow_to(victim_index, m_new_flow_insert_index);
      flow_index = row_begin + m_new_flow_insert_index;
#ifdef WITH_CTT
      if (m_flow_table[flow_index.value()]->is_in_ctt && !m_flow_table[flow_index.value()]->is_waiting_for_export) {
         m_flow_table[flow_index.value()]->is_waiting_for_export = true;
         send_export_request_to_ctt(m_flow_table[flow_index.value()]->m_flow.flow_hash_ctt);
         m_flow_table[flow_index.value()]->export_time = {pkt.ts.tv_sec + 1, pkt.ts.tv_usec};
      }
#endif /* WITH_CTT */
      plugins_pre_export(m_flow_table[flow_index.value()]->m_flow);
      export_flow(flow_index.value(), FLOW_END_NO_RES);

      m_cache_stats.not_empty++;
   }
   create_record(pkt, flow_index.value(), hash_value.value());
   export_expired(pkt.ts);
   return 0;
}

bool NHTFlowCache::try_to_export_on_active_timeout(size_t flow_index, const timeval& now) noexcept
{
   if (!m_flow_table[flow_index]->is_empty() && now.tv_sec - m_flow_table[flow_index]->m_flow.time_first.tv_sec >= m_active) {
      return try_to_export(flow_index, true, now, FLOW_END_ACTIVE);
   }
   return false;
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
   }
   return FLOW_END_INACTIVE;
}

void NHTFlowCache::export_expired(time_t now)
{
   export_expired({now, 0});
}

void NHTFlowCache::export_expired(const timeval& now)
{
   for (size_t i = m_last_exported_on_timeout_index; i < m_last_exported_on_timeout_index + m_new_flow_insert_index; i++) {
      try_to_export_on_inactive_timeout(i, now);
   }
   m_last_exported_on_timeout_index = (m_last_exported_on_timeout_index + m_new_flow_insert_index) & (m_cache_size - 1);
}

bool NHTFlowCache::create_hash_key(const Packet& packet)
{
   if (packet.ip_version == IP::v4) {
      m_key = FlowKeyv4::save_direct(packet);
      m_key_reversed = FlowKeyv4::save_reversed(packet);
      return true;
   } else if (packet.ip_version == IP::v6) {
      m_key = FlowKeyv6::save_direct(packet);
      m_key_reversed = FlowKeyv6::save_reversed(packet);
      return true;
   }
   return false;
}

void NHTFlowCache::print_report() const
{
   const float tmp = static_cast<float>(m_cache_stats.lookups) / m_cache_stats.hits;

   std::cout << "Hits: " << m_cache_stats.hits << std::endl;
   std::cout << "Empty: " << m_cache_stats.empty << std::endl;
   std::cout << "Not empty: " << m_cache_stats.not_empty << std::endl;
   std::cout << "Expired: " << m_cache_stats.exported << std::endl;
   std::cout << "Flushed: " << m_cache_stats.flushed << std::endl;
   std::cout << "Average Lookup:  " << tmp << std::endl;
   std::cout << "Variance Lookup: " << static_cast<float>(m_cache_stats.lookups2) / m_cache_stats.hits - tmp * tmp << std::endl;
#ifdef WITH_CTT
    std::cout << "CTT offloaded: " << m_cache_stats.ctt_offloaded << std::endl;
#endif /* WITH_CTT */
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
#ifdef WITH_CTT
void NHTFlowCache::set_ctt_config(const std::shared_ptr<CttController>& ctt_controller)
{
   m_ctt_controller = ctt_controller;
}
#endif /* WITH_CTT */

}
