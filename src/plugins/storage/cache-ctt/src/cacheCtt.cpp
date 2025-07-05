/**
 * \file cache.cpp
 * \brief NHTFlowCache extension with CTT support
 * \author Zainullin Damir <zaidamilda@gmail.com>
 * \date 2025
 */
/*
 * Copyright (C) 2023 CESNET
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
 */

#include "cacheCtt.hpp"

#include <ipfixprobe/ring.h>
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <ratio>
#include <sys/time.h>
#include <optional>
#include <endian.h>
#include <algorithm>
#include <fstream>
#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>


#include "cacheOptParserCtt.hpp"
#include "../../cache/src/flowKeyFactory.hpp"

namespace ipxp {

static const PluginManifest cachePluginManifest = {
   .name = "cache-ctt",
   .description = "Storage plugin implemented as a hash table with ctt support.",
   .pluginVersion = "1.0.0",
   .apiVersion = "1.0.0",
   .usage =
      []() {
         CacheOptParserCtt parser;
         parser.usage(std::cout);
      },
};

OptionsParser * NHTFlowCacheCtt::get_parser() const
{
   return new CacheOptParserCtt();
}

std::string NHTFlowCacheCtt::get_name() const noexcept
{
   return "cache-ctt";
}

NHTFlowCacheCtt::NHTFlowCacheCtt(const std::string& params, ipx_ring_t* queue)
: NHTFlowCache(false)
{
   set_queue(queue);
	init(params.c_str());
}

void NHTFlowCacheCtt::init(const char* params) 
{
   std::unique_ptr<CacheOptParserCtt> parser(static_cast<CacheOptParserCtt*>(get_parser()));
   try {
      parser->parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }
   m_offload_mode = parser->m_offload_mode;
   m_offload_threshold = parser->m_offload_threshold;
   m_ctt_remove_queue_size = parser->m_ctt_remove_queue_size;
   if (parser->m_split_biflow) {
      throw PluginError("CTT does not support uniflows");
   }
   NHTFlowCache::init(params);
}

void NHTFlowCacheCtt::allocate_table()
{
   try {
      const size_t size = m_cache_size + m_queue_size;
      NHTFlowCache::m_flow_table = std::make_unique<FlowRecord*[]>(size);
      m_flows = std::make_unique<FlowRecordCtt[]>(size + m_ctt_remove_queue_size);
      m_ctt_remove_queue.set_buffer(m_flows.get() + size, m_ctt_remove_queue_size);
      m_flow_table = reinterpret_cast<FlowRecordCtt**>(NHTFlowCache::m_flow_table.get());
      std::for_each(m_flow_table, m_flow_table + size, [index = 0, this](FlowRecordCtt*& flow) mutable  {
         flow = &m_flows[index++];
      });
   } catch (std::bad_alloc &e) {
      throw PluginError("not enough memory for flow cache allocation");
   }
   m_flow_table = reinterpret_cast<FlowRecordCtt**>(NHTFlowCache::m_flow_table.get());
}

void NHTFlowCacheCtt::export_flow(FlowRecord** flow, int reason)
{
   m_ctt_stats.real_processed_packets += (*flow)->m_flow.src_packets + (*flow)->m_flow.dst_packets;
   NHTFlowCache::export_flow(flow, reason);
}

void NHTFlowCacheCtt::finish()
{
   std::for_each(m_flow_table, m_flow_table + m_cache_size, [&](FlowRecordCtt*& flow_record) {
      if (!flow_record->is_empty()) {
         if (flow_record->is_in_ctt()) {
            throw PluginError("Flow record is in CTT, but it was not exported before cache termination");
            m_ctt_stats.total_requests_count++;
            m_ctt_controller->remove_record_without_notification(flow_record->m_flow.flow_hash_ctt);
         }
         plugins_pre_export(flow_record->m_flow);
         export_flow(reinterpret_cast<FlowRecord**>(&flow_record), FLOW_END_FORCED);
      }
   });
   print_report();
}

void NHTFlowCacheCtt::close()
{
   NHTFlowCache::close();
   m_flows.reset();
}

NHTFlowCacheCtt::~NHTFlowCacheCtt() 
{
   close();
}

void NHTFlowCacheCtt::flush_ctt(const timeval now) noexcept
{
   constexpr size_t BLOCK_SIZE = 8;
   for(size_t current_index = m_prefinish_index; current_index < m_prefinish_index + BLOCK_SIZE; current_index++) {
      FlowRecordCtt* flow_record = m_flow_table[current_index];
      if (flow_record->is_empty() || !flow_record->is_in_ctt()) {
         continue;
      }

      m_ctt_flow_seen = true;
      if (flow_record->is_waiting_ctt_response() && *flow_record->last_request_time + CTT_REQUEST_TIMEOUT > now) {
         continue;
      } else if (flow_record->is_waiting_ctt_response()) {
         m_ctt_stats.lost_requests_count++;
         m_ctt_stats.flush_ctt_lost_requests++;
      }
      m_ctt_flows_flushed++;
      m_ctt_stats.total_requests_count++;
      m_ctt_controller->export_record(flow_record->m_flow.flow_hash_ctt);
      flow_record->last_request_time = now;
      
   };

   m_prefinish_index = (m_prefinish_index + BLOCK_SIZE) % m_cache_size;
   if (m_prefinish_index == 0) {
      m_table_flushed = !m_ctt_flow_seen; 
      m_ctt_flow_seen = false;
   }

   if (m_ctt_flows_flushed >= 16) {
      m_ctt_flows_flushed = 0;
      usleep(400);   
   }
}

std::optional<feta::OffloadMode> NHTFlowCacheCtt::get_offload_mode(size_t flow_index) noexcept
{
   if (!m_offload_mode.has_value() || !m_flow_table[flow_index]->can_be_offloaded) {
      return std::nullopt;
   }

   if (no_data_required(m_flow_table[flow_index]->m_flow) 
         && *m_offload_mode == feta::OffloadMode::DROP_PACKET_DROP_META 
         && m_flow_table[flow_index]->m_flow.src_packets + m_flow_table[flow_index]->m_flow.dst_packets >= m_offload_threshold
         && !m_ctt_remove_queue.find(m_flow_table[flow_index]->m_flow.flow_hash)) {
      m_ctt_stats.drop_packet_offloaded++;
      return feta::OffloadMode::DROP_PACKET_DROP_META;
   }

   if (only_metadata_required(m_flow_table[flow_index]->m_flow) 
         && *m_offload_mode == feta::OffloadMode::TRIM_PACKET_META 
         && m_flow_table[flow_index]->m_flow.src_packets + m_flow_table[flow_index]->m_flow.dst_packets >= m_offload_threshold
         && !m_ctt_remove_queue.find(m_flow_table[flow_index]->m_flow.flow_hash)) {
      m_ctt_stats.trim_packet_offloaded++;
      return feta::OffloadMode::TRIM_PACKET_META;
   }

   return std::nullopt;
}

void NHTFlowCacheCtt::export_and_reuse_flow(size_t flow_index) noexcept
{
   if (!m_flow_table[flow_index]->is_in_ctt()) {
      return NHTFlowCache::export_and_reuse_flow(flow_index);
   }
   auto& flow_record = *m_flow_table[flow_index];
   m_flow_table[flow_index] = m_ctt_remove_queue.add(m_flow_table[flow_index]);
   *m_flow_table[flow_index] = flow_record;
   m_flow_table[flow_index]->reuse();
}

void NHTFlowCacheCtt::create_record(const Packet& packet, size_t flow_index, size_t hash_value) noexcept
{
   m_cache_stats.flows_in_cache++;
   m_flow_table[flow_index]->create(packet, hash_value);
   const size_t post_create_return_flags = plugins_post_create(m_flow_table[flow_index]->m_flow, packet);
   if (post_create_return_flags & ProcessPlugin::FlowAction::FLUSH) {
      NHTFlowCache::export_flow(flow_index);
      m_cache_stats.flushed++;
      return;
   }
   // if metadata are valid, add flow hash ctt to the flow record
   if (!packet.cttmeta.has_value()) {
      return;
   }
   m_flow_table[flow_index]->m_flow.flow_hash_ctt = packet.cttmeta->flow_hash;
   if (const std::optional<feta::OffloadMode> offload_mode = get_offload_mode(flow_index); offload_mode.has_value()) {
      offload_flow_to_ctt(flow_index, *offload_mode);
   }
}

void NHTFlowCacheCtt::offload_flow_to_ctt(size_t flow_index, feta::OffloadMode offload_mode) noexcept 
{
   m_ctt_stats.total_requests_count++;
   m_ctt_controller->create_record(m_flow_table[flow_index]->m_flow, m_dma_channel, offload_mode);
   m_ctt_stats.flows_offloaded++;
   m_flow_table[flow_index]->offload_mode = offload_mode;
}

void NHTFlowCacheCtt::try_to_add_flow_to_ctt(size_t flow_index) noexcept
{
   if (m_flow_table[flow_index]->is_in_ctt() || m_flow_table[flow_index]->m_flow.flow_hash_ctt == 0) {
      return;
   }
   if (const std::optional<feta::OffloadMode> offload_mode = get_offload_mode(flow_index); offload_mode.has_value()) {
      offload_flow_to_ctt(flow_index, *offload_mode);
   }
}

int NHTFlowCacheCtt::update_flow(Packet& packet, size_t flow_index) noexcept
{
   int res = NHTFlowCache::update_flow(packet, flow_index);
   if (!m_flow_table[flow_index]->is_empty()) {
      try_to_add_flow_to_ctt(flow_index);     
   }
   return res;
}

void NHTFlowCacheCtt::send_export_request_to_ctt(size_t ctt_flow_hash) noexcept
{
   m_ctt_stats.total_requests_count++;
   m_ctt_controller->export_record(ctt_flow_hash);
}

void NHTFlowCacheCtt::try_to_export(size_t flow_index, bool call_pre_export, int reason) noexcept
{
   if (m_flow_table[flow_index]->is_in_ctt()) {
      m_flow_table[flow_index] = m_ctt_remove_queue.add(m_flow_table[flow_index]);
      return;
   }
   if (call_pre_export) {
      plugins_pre_export(m_flow_table[flow_index]->m_flow);
   }
   NHTFlowCache::export_flow(flow_index, reason);
}

int convert_ctt_export_reason_to_ipfxiprobe(feta::ExportReason ctt_reason, feta::MuExportReason mu_reason) noexcept
{
   switch (ctt_reason) {
      case feta::ExportReason::EXPORT_BY_SW:
         return FLOW_END_FORCED;
      case feta::ExportReason::FULL_CTT:
         return FLOW_END_FORCED;
      case feta::ExportReason::EXPORT_BY_MU:
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::COUNTER_OVERFLOW)) {
            return FLOW_END_FORCED;
         }
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::TCP_CONN_END)) {
            return FLOW_END_EOF;
         }
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::ACTIVE_TIMEOUT)) {
               return FLOW_END_ACTIVE;
         }
         [[fallthrough]];
      default:
         return FLOW_END_NO_RES;
   }
}

void update_ctt_export_stats(feta::ExportReason ctt_reason, feta::MuExportReason mu_reason, CttStats::ExportReasons& reasons) noexcept
{
   switch (ctt_reason) {
      case feta::ExportReason::EXPORT_BY_SW:
         reasons.by_request++;
         break;
      case feta::ExportReason::FULL_CTT:
         reasons.ctt_full++;
         break;
      case feta::ExportReason::RESERVED:
         reasons.reserved++;
         break;
      case feta::ExportReason::EXPORT_BY_MU:
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::COUNTER_OVERFLOW)) {
            reasons.counter_overflow++;
         }
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::TCP_CONN_END)) {
            reasons.tcp_eof++;
         }
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::ACTIVE_TIMEOUT)) {
            reasons.active_timeout++;
         }
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::FLOW_COLLISION)) {
            reasons.hash_collision++;
         }
         break;
   }
}

void NHTFlowCacheCtt::update_advanced_ctt_export_stats(const feta::CttExportPkt& export_data) noexcept
{
   feta::ExportReason ctt_reason = export_data.fields.rsn;
   feta::MuExportReason mu_reason = export_data.fields.ursn;

   switch (ctt_reason) {
      case feta::ExportReason::EXPORT_BY_SW:
         m_ctt_stats.advanced_export_reasons.by_request[export_data.fields.wb]++;
         break;
      case feta::ExportReason::FULL_CTT:
         m_ctt_stats.advanced_export_reasons.ctt_full[export_data.fields.wb]++;
         break;
      case feta::ExportReason::RESERVED:
         m_ctt_stats.advanced_export_reasons.reserved[export_data.fields.wb]++;
         break;
      case feta::ExportReason::EXPORT_BY_MU:
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::COUNTER_OVERFLOW)) {
            m_ctt_stats.advanced_export_reasons.counter_overflow[export_data.fields.wb]++;
         }
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::TCP_CONN_END)) {
            m_ctt_stats.advanced_export_reasons.tcp_eof[export_data.fields.wb]++;
         }
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::ACTIVE_TIMEOUT)) {
            m_ctt_stats.advanced_export_reasons.active_timeout[export_data.fields.wb]++;
         }
         if (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::FLOW_COLLISION)) {
            m_ctt_stats.advanced_export_reasons.hash_collision[export_data.fields.wb]++;
         }
         break;
   }
}

static bool is_counter_overflow(feta::ExportReason ctt_reason, feta::MuExportReason mu_reason) noexcept
{
   return ctt_reason == feta::ExportReason::EXPORT_BY_MU && (static_cast<uint8_t>(mu_reason) & static_cast<uint8_t>(feta::MuExportReason::COUNTER_OVERFLOW));
}

static void update_packet_counters_from_external_export(Flow& flow, const feta::CttRecord& state) noexcept
{
   flow.src_packets += state.pkts;
   flow.dst_packets += state.pkts_rev;
   flow.src_bytes += state.bytes;
   flow.dst_bytes += state.bytes_rev;
   flow.time_last.tv_sec = state.ts_last.time_sec;
   flow.time_last.tv_usec = state.ts_last.time_ns / 1000;
   if (flow.ip_proto == 6) {
      flow.src_tcp_flags |= state.tcp_flags;
      flow.dst_tcp_flags |= state.tcp_flags_rev;
   }
}

static bool is_hash_collision(feta::ExportReason ctt_reason, feta::MuExportReason mu_reason) noexcept
{
   return ctt_reason == feta::ExportReason::EXPORT_BY_MU && (mu_reason & feta::MuExportReason::FLOW_COLLISION);
}

static bool is_tcp_restart(feta::ExportReason ctt_reason, feta::MuExportReason mu_reason) noexcept 
{
   return ctt_reason == feta::ExportReason::EXPORT_BY_MU && (mu_reason & feta::MuExportReason::TCP_CONN_END);
}

static bool is_active_timeout(feta::ExportReason ctt_reason, feta::MuExportReason mu_reason) noexcept
{
   return ctt_reason == feta::ExportReason::EXPORT_BY_MU && (mu_reason & feta::MuExportReason::ACTIVE_TIMEOUT);
}

static bool is_ctt_full(feta::ExportReason ctt_reason) noexcept
{
   return ctt_reason == feta::ExportReason::FULL_CTT;
}

std::optional<NHTFlowCacheCtt::CttFlowSearch> NHTFlowCacheCtt::find_flow_from_ctt_export(const feta::CttExportPkt& export_data) noexcept
{
   const IP ip_version = export_data.record.ip_ver == feta::IpVersion::IPV4 ? IP::v4 : IP::v6;

   const auto [key, swapped] = FlowKeyFactory::create_sorted_key(export_data.record.ip_src.data(), export_data.record.ip_dst.data(),
      export_data.record.port_src, export_data.record.port_dst, export_data.record.l4_proto, ip_version, FlowKeyFactory::EMPTY_VLAN);

   const auto [search, source_to_destination] = find_flow_index(key, swapped);
   const auto [row, flow_index, hash_value] = search;

   FlowRecordCtt** flow_record_ptr = m_ctt_remove_queue.find(hash_value);

   bool is_from_remove_queue = true;
   if (flow_record_ptr == nullptr && flow_index.has_value()) {
      flow_record_ptr = &m_flow_table[*flow_index];
      is_from_remove_queue = false;
   }
   if (flow_record_ptr == nullptr 
         || !(*flow_record_ptr)->is_in_ctt()
         || !(*flow_record_ptr)->offload_mode.has_value()) {
      return std::nullopt;
   }
   return CttFlowSearch{
      .flow_record = flow_record_ptr,
      .is_from_remove_queue = is_from_remove_queue
   };
}

void NHTFlowCacheCtt::process_external_export(const Packet& pkt) noexcept
{
   m_ctt_stats.export_packets++;
   if (pkt.packet_len != sizeof(feta::CttExportPkt)) {
      m_ctt_stats.export_packets_parsing_failed++;
      return;
   }
   feta::CttExportPkt export_data = feta::CttExportPkt::deserialize(reinterpret_cast<std::byte*>(const_cast<uint8_t*>(pkt.packet)));

   m_ctt_stats.wb_before_pv1[export_data.fields.wb]++;
   update_ctt_export_stats(export_data.fields.rsn, export_data.fields.ursn, m_ctt_stats.export_reasons_before_pv1);

   if (export_data.fields.pv != 1) {
      m_ctt_stats.pv_zero++;
      return; // Drop invalid packet
   }

   m_ctt_stats.wb_after_pv1[export_data.fields.wb]++;
   update_ctt_export_stats(export_data.fields.rsn, export_data.fields.ursn, m_ctt_stats.export_reasons_after_pv1);
   update_advanced_ctt_export_stats(export_data);

   std::optional<NHTFlowCacheCtt::CttFlowSearch> flow_search = find_flow_from_ctt_export(export_data);
   if (!flow_search.has_value()) {
      m_ctt_stats.export_packets_for_missing_flow++;
      return;
   }

   auto [flow_record_ptr, is_from_remove_queue] = *flow_search;
   FlowRecordCtt*& flow_record = *flow_record_ptr; 

   // Two flows with different ipfixprobe keys but same CTT flow hash tried to create flow at the same time 
   if (export_data.fields.wb && export_data.fields.rsn == feta::ExportReason::EXPORT_BY_SW) {
      flow_record->can_be_offloaded = false;
      flow_record->offload_mode.reset();
      m_ctt_stats.flows_removed++;
      if (is_from_remove_queue) {
         NHTFlowCache::export_flow(reinterpret_cast<FlowRecord**>(&flow_record));
      }
      return;
   }

   if (!export_data.fields.wb && flow_record->offload_mode == feta::OffloadMode::TRIM_PACKET_META) {
      flow_record->last_request_time.reset();
   }

   if (flow_record->offload_mode == feta::OffloadMode::DROP_PACKET_DROP_META) {
      flow_record->last_request_time.reset();
      update_packet_counters_from_external_export(flow_record->m_flow, export_data.record);
   }

   if (!export_data.fields.wb && flow_record->offload_mode == feta::OffloadMode::DROP_PACKET_DROP_META 
         && (is_tcp_restart(export_data.fields.rsn, export_data.fields.ursn)
         || export_data.fields.rsn == feta::ExportReason::EXPORT_BY_SW)) {
      NHTFlowCache::export_flow(reinterpret_cast<FlowRecord**>(&flow_record));
      m_ctt_stats.flows_removed++;
      return;
   }

   //Counter overflow is not a flow end reason, but it is used to update ipfixprobe flow counters
   if (is_counter_overflow(export_data.fields.rsn, export_data.fields.ursn) || is_active_timeout(export_data.fields.rsn, export_data.fields.ursn)) {
      return;
   }

   // Mark flow as not offloadable to avoid ping-pong with CTT
   if (is_hash_collision(export_data.fields.rsn, export_data.fields.ursn) || is_ctt_full(export_data.fields.rsn)) {
      flow_record->can_be_offloaded = false;
   }

   // Flow is not in the CTT anymore
   if (!export_data.fields.wb) {
      flow_record->offload_mode.reset();
      m_ctt_stats.flows_removed++;
      if (is_from_remove_queue) {
         NHTFlowCache::export_flow(reinterpret_cast<FlowRecord**>(&flow_record));
      }
      return;
   }
}

int NHTFlowCacheCtt::put_pkt(Packet& packet)
{
   if (packet.external_export) {
      process_external_export(packet);
   }
   if (m_input_terminted) {
      flush_ctt(packet.ts);
   }
   if (packet.external_export || m_input_terminted) {
      return 0;
   }
   return NHTFlowCache::put_pkt(packet);
}

size_t NHTFlowCacheCtt::find_victim(CacheRowSpan& row) const noexcept
{
   auto begin = reinterpret_cast<FlowRecordCtt**>(&row[0]);
   for (size_t i = m_line_size; i > 0; i-- ) {
      if (!begin[i - 1]->is_in_ctt() || 
         (begin[i - 1]->offload_mode.has_value() 
            && begin[i - 1]->offload_mode.value() == feta::OffloadMode::TRIM_PACKET_META)) {
         return i - 1;
      }
   }
   return m_line_size - 1;
}

bool NHTFlowCacheCtt::requires_input() const
{
   return !m_table_flushed;
}

void NHTFlowCacheCtt::export_expired(const timeval& now)
{
   auto [sent_request, lost_request] = m_ctt_remove_queue.resend_lost_requests(now);
   m_ctt_stats.remove_queue_lost_requests += lost_request;
   m_ctt_stats.lost_requests_count += lost_request;
   m_ctt_stats.total_requests_count += sent_request;
    if (m_input_terminted) {
      flush_ctt(now);
      return;
   }
   NHTFlowCache::export_expired(now);
}

void NHTFlowCacheCtt::print_report() const
{
   const float tmp = static_cast<float>(m_cache_stats.lookups) / m_cache_stats.hits;
   std::cout << "Hits: " << m_cache_stats.hits << "\n";
   std::cout << "Empty: " << m_cache_stats.empty << "\n";
   std::cout << "Not empty: " << m_cache_stats.not_empty << "\n";
   std::cout << "Expired: " << m_cache_stats.exported << "\n";
   std::cout << "Flushed: " << m_cache_stats.flushed << "\n";
   std::cout << "Average Lookup:  " << tmp << "\n";
   std::cout << "Variance Lookup: " << static_cast<float>(m_cache_stats.lookups2) / m_cache_stats.hits - tmp * tmp << "\n";
   std::cout << "Flow end stats: " << "\n";
   std::cout << "Flow end reason: active timeout: " << m_flow_end_reason_stats.active_timeout << "\n";
   std::cout << "Flow end reason: inactive timeout: " << m_flow_end_reason_stats.inactive_timeout << "\n";
   std::cout << "Flow end reason: end of flow: " << m_flow_end_reason_stats.end_of_flow << "\n";
   std::cout << "Flow end reason: collision: " << m_flow_end_reason_stats.collision << "\n";
   std::cout << "Flow end reason: forced: " << m_flow_end_reason_stats.forced << "\n";
   std::cout << "Really processed: " << m_ctt_stats.real_processed_packets << "\n";
   std::cout << "CTT offloaded: " << m_ctt_stats.flows_offloaded << "\n";
   std::cout << "CTT trim packet offloaded: " << m_ctt_stats.trim_packet_offloaded << "\n";
   std::cout << "CTT drop packet offloaded: " << m_ctt_stats.drop_packet_offloaded << "\n";
   std::cout << "CTT flows removed after export packet: " << m_ctt_stats.flows_removed << "\n";
   std::cout << "CTT sent export packets:" << m_ctt_stats.export_packets << "\n";
   std::cout << "CTT export packets parsing failed:" << m_ctt_stats.export_packets_parsing_failed << "\n";
   std::cout << "CTT export packet failed to find corresponding flow:" << m_ctt_stats.export_packets_for_missing_flow << "\n";
}

telemetry::Dict get_export_reasons_telemetry(CttStats::ExportReasons& reasons) noexcept 
{
   telemetry::Dict dict;
   dict["BySW"] = reasons.by_request;
   dict["CttFull"] = reasons.ctt_full;
   dict["Reserved"] = reasons.reserved;
   dict["CounterOverflow"] = reasons.counter_overflow;
   dict["TcpEof"] = reasons.tcp_eof;
   dict["ActiveTimeout"] = reasons.active_timeout;
   dict["HashCollision"] = reasons.hash_collision;
   dict["Total"] = reasons.by_request + reasons.ctt_full + reasons.reserved + reasons.counter_overflow +
      reasons.tcp_eof + reasons.active_timeout + reasons.hash_collision;
   return dict;

}

telemetry::Dict NHTFlowCacheCtt::get_ctt_telemetry() noexcept
{
   telemetry::Dict dict;
   dict["CttRequests"] = m_ctt_stats.total_requests_count;
   dict["CttRemoveQueueSize"] = m_ctt_remove_queue.size();
   dict["CttLostRequests"] = m_ctt_stats.lost_requests_count;
   dict["FlowsInCtt"] = m_ctt_stats.flows_offloaded - m_ctt_stats.flows_removed;
   dict["ExportPacketsForMissingFlow"] = m_ctt_stats.export_packets_for_missing_flow;
   dict["CttHashCollision"] = std::to_string(m_ctt_stats.advanced_export_reasons.hash_collision[0]) +
      " (WB0), " + std::to_string(m_ctt_stats.advanced_export_reasons.hash_collision[1]) + " (WB1)";
   dict["CttExportPackets"] = m_ctt_stats.export_packets;
   dict["CttFull"] = std::to_string(m_ctt_stats.advanced_export_reasons.ctt_full[0]) +
      " (WB0), " + std::to_string(m_ctt_stats.advanced_export_reasons.ctt_full[1]) + " (WB1)";
   dict["CttEof"] = std::to_string(m_ctt_stats.advanced_export_reasons.tcp_eof[0]) + 
      " (WB0), " + std::to_string(m_ctt_stats.advanced_export_reasons.tcp_eof[1]) + " (WB1)";
   dict["CttActiveTimeout"] = std::to_string(m_ctt_stats.advanced_export_reasons.active_timeout[0]) +
      " (WB0), " + std::to_string(m_ctt_stats.advanced_export_reasons.active_timeout[1]) + " (WB1)";
   dict["CttCounterOverflow"] = std::to_string(m_ctt_stats.advanced_export_reasons.counter_overflow[0]) +
      " (WB0), " + std::to_string(m_ctt_stats.advanced_export_reasons.counter_overflow[1]) + " (WB1)";
   dict["CttSwExport"] = std::to_string(m_ctt_stats.advanced_export_reasons.by_request[0]) +
      " (WB0), " + std::to_string(m_ctt_stats.advanced_export_reasons.by_request[1]) + " (WB1)";
   dict["CttRemoveQueueLostRequests"] = m_ctt_stats.remove_queue_lost_requests;
   dict["CttFlushCttLostRequests"] = m_ctt_stats.flush_ctt_lost_requests;
   dict["CttPvZero"] = m_ctt_stats.pv_zero;
   dict["ControllerCreateRequests"] = m_ctt_controller->get_request_stats().create_record_requests;
   dict["ControllerExportAndDeleteRequests"] = m_ctt_controller->get_request_stats().export_and_delete_requests;
   dict["CttFlowsOffloaded"] = m_ctt_stats.flows_offloaded;
   dict["CttFlowsRemoved"] = m_ctt_stats.flows_removed;
   dict["CttParsingFailed"] = m_ctt_stats.export_packets_parsing_failed;
   dict["WbBeforePv1"] = std::to_string(m_ctt_stats.wb_before_pv1[0]) + " = 0, " + 
      std::to_string(m_ctt_stats.wb_before_pv1[1]) + " = 1";
   dict["WbAfterPv1"] = std::to_string(m_ctt_stats.wb_after_pv1[0]) + " = 0, " +
      std::to_string(m_ctt_stats.wb_after_pv1[1]) + " = 1";
   dict["LibcttQueueSize(DMA shared)"] = m_ctt_controller->get_approximate_queue_size();
   return dict;
}

telemetry::Dict NHTFlowCacheCtt::get_libctt_telemetry() noexcept
{
   telemetry::Dict dict;
   auto [ctt_stats_succ, ctt_stats_err] = m_ctt_controller->get_queue_stats();
   dict["CommandsOffloaded"] = std::to_string(ctt_stats_succ.commands_offloaded) + " (success), " + 
      std::to_string(ctt_stats_err.commands_offloaded) + " (error)";
   dict["ReadOffloaded"] = std::to_string(ctt_stats_succ.read_offloaded) + " (success), " + 
      std::to_string(ctt_stats_err.read_offloaded) + " (error)";
   dict["WriteOffloaded"] = std::to_string(ctt_stats_succ.write_offloaded) + " (success), " + 
      std::to_string(ctt_stats_err.write_offloaded) + " (error)";
   dict["DeleteOffloaded"] = std::to_string(ctt_stats_succ.delete_offloaded) + " (success), " + 
      std::to_string(ctt_stats_err.delete_offloaded) + " (error)";
   dict["ExportOffloaded"] = std::to_string(ctt_stats_succ.export_offloaded) + " (success), " + 
      std::to_string(ctt_stats_err.export_offloaded) + " (error)";
   dict["ExportAndWriteOffloaded"] = std::to_string(ctt_stats_succ.export_and_write_offloaded) + " (success), " + 
      std::to_string(ctt_stats_err.export_and_write_offloaded) + " (error)";
   dict["ExportAndDeleteOffloaded"] = std::to_string(ctt_stats_succ.export_and_delete_offloaded) + " (success), " + 
      std::to_string(ctt_stats_err.export_and_delete_offloaded) + " (error)";
   dict["RmwOffloaded"] = std::to_string(ctt_stats_succ.rmw_offloaded) + " (success), " + 
      std::to_string(ctt_stats_err.rmw_offloaded) + " (error)";
   return dict;
}

void NHTFlowCacheCtt::set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir)
{
   telemetry::FileOps cacheStats = {[this]() -> telemetry::Content { return get_cache_telemetry(); }, nullptr};
   register_file(dir, "cache-stats", cacheStats);

   telemetry::FileOps cttStats = {[this]() -> telemetry::Content { return get_ctt_telemetry(); }, nullptr};
   register_file(dir, "ctt-stats", cttStats);

   if (m_enable_fragmentation_cache) {
      m_fragmentation_cache.set_telemetry_dir(dir);
   }

   telemetry::FileOps reasonsBeforePv1 = {[this]() -> telemetry::Content { 
      return get_export_reasons_telemetry(m_ctt_stats.export_reasons_before_pv1); 
   }, nullptr};
   register_file(dir, "ctt-export-reasons-before-pv1", reasonsBeforePv1);

   telemetry::FileOps reasonsAfterPv1 = {[this]() -> telemetry::Content { 
      return get_export_reasons_telemetry(m_ctt_stats.export_reasons_after_pv1); 
   }, nullptr};
   register_file(dir, "ctt-export-reasons-after-pv1", reasonsAfterPv1);

   telemetry::FileOps libcttStats = {[this]() -> telemetry::Content { return get_libctt_telemetry(); }, nullptr};
   register_file(dir, "libctt-stats", libcttStats);
}


void NHTFlowCacheCtt::init_ctt(const CttConfig& ctt_config)
{
   m_dma_channel = ctt_config.dma_channel;
   m_ctt_controller.emplace(ctt_config.nfb_device, ctt_config.dma_channel/16);
   m_ctt_remove_queue.set_ctt_controller(&*m_ctt_controller);
}

static const PluginRegistrar<NHTFlowCacheCtt, StoragePluginFactory>
	cacheRegistrar(cachePluginManifest);
}
