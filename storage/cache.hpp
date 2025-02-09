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

#include <ctime>
#include <string>
#include <ipfixprobe/storage.hpp>
#include <optional>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/telemetry-utils.hpp>
#include <unordered_map>
#include <ipfixprobe/cttmeta.hpp>
#include "fragmentationCache/fragmentationCache.hpp"
#include "cacheOptParser.hpp"
#include "cacheRowSpan.hpp"
#include "flowKey.tpp"
#include "flowRecord.hpp"
#include "cttController.hpp"
#include "cacheStats.hpp"

namespace ipxp {

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

   int put_pkt(Packet& packet) override;
   void export_expired(time_t now) override;

#ifdef WITH_CTT
   void export_external(const Packet& pkt) noexcept override;
#endif /* WITH_CTT */

   /**
     * @brief Set and configure the telemetry directory where cache stats will be stored.
     */
   void set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir) override;

private:
   uint32_t m_cache_size{0};
   uint32_t m_line_size{0};
   uint32_t m_line_mask{0};
   uint32_t m_new_flow_insert_index{0};
   uint32_t m_queue_size{0};
   uint32_t m_queue_index{0};
   uint32_t m_last_exported_on_timeout_index{0};

   uint32_t m_active{0};
   uint32_t m_inactive{0};
   bool m_split_biflow{false};
   bool m_enable_fragmentation_cache{true};
   //std::variant<FlowKeyv4, FlowKeyv6> m_key;
   //std::variant<FlowKeyv4, FlowKeyv6> m_key_reversed;
   std::vector<FlowRecord*> m_flow_table;
   std::vector<FlowRecord> m_flows;
   std::function<size_t(const uint8_t* data, size_t length)> m_hash_function;

   FragmentationCache m_fragmentation_cache{0,0};
   FlowEndReasonStats m_flow_end_reason_stats = {};
   FlowRecordStats m_flow_record_stats = {};
   FlowCacheStats m_cache_stats = {};
#ifdef WITH_CTT
   CttStats m_ctt_stats = {};
   void set_ctt_config(const std::shared_ptr<CttController>& ctt_controller, uint8_t dma_channel) override;
   //std::string m_ctt_device;
   //unsigned m_ctt_comp_index;
   uint8_t m_dma_channel;
   std::shared_ptr<CttController> m_ctt_controller;
   //std::unordered_map<size_t, int> m_hashes_in_ctt;
   //size_t m_ctt_hash_collision{0};
   void update_ctt_export_stats(CttExportReason ctt_reason, ManagementUnitExportReason mu_reason) noexcept;
#endif /* WITH_CTT */

   void try_to_fill_ports_to_fragmented_packet(Packet& packet);
   void flush(Packet &pkt, size_t flow_index, int return_flags);

   static uint8_t get_export_reason(const Flow &flow);
   void finish();
   void allocate_table();
   void update_flow_end_reason_stats(uint8_t reason);
   void update_flow_record_stats(uint64_t packets_count);
   telemetry::Content get_cache_telemetry();
   void prefetch_export_expired() const;
   void get_parser_options(CacheOptParser& parser) noexcept;
   void push_to_export_queue(size_t flow_index) noexcept;
   std::pair<CacheRowSpan, std::variant<std::pair<size_t, bool>, size_t>>
   find_flow_index(const std::variant<FlowKeyv4, FlowKeyv6>& key,
      const std::variant<FlowKeyv4, FlowKeyv6>& key_reversed, const std::optional<uint16_t>& vlan_id = std::nullopt) noexcept;
   std::tuple<CacheRowSpan, std::optional<size_t>, size_t>
   find_row(const std::variant<FlowKeyv4, FlowKeyv6>& key, const std::optional<uint16_t>& vlan_id = std::nullopt) noexcept;
   bool try_to_export_on_inactive_timeout(size_t flow_index, const timeval& now) noexcept;
   bool try_to_export_on_active_timeout(size_t flow_index, const timeval& now) noexcept;
   void export_flow(size_t flow_index, int reason);
   void export_flow(size_t flow_index);
   int process_flow(Packet& packet, size_t flow_index, bool flow_is_waiting_for_export) noexcept;
   bool try_to_export_delayed_flow(const Packet& packet, size_t flow_index) noexcept;
   void create_record(const Packet& packet, size_t flow_index, size_t hash_value) noexcept;
   bool try_to_export(size_t flow_index, bool call_pre_export, const timeval& now, int reason) noexcept;
   bool try_to_export(size_t flow_index, bool call_pre_export, const timeval& now) noexcept;
   void print_report() const;
   void send_export_request_to_ctt(size_t ctt_flow_hash) noexcept;
   void export_expired(const timeval& now);
   void try_to_add_flow_to_ctt(size_t flow_index) noexcept;
   bool needs_to_be_offloaded(size_t flow_index) const noexcept;
};

}
#endif /* IPXP_STORAGE_CACHE_HPP */