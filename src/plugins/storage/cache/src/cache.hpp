/**
 * \file cache.hpp
 * \brief "NewHashTable" flow cache
 * \author Martin Zadnik <zadnik@cesnet.cz>
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \author Pavel Siska <siska@cesnet.cz>
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \date 2014
 * \date 2015
 * \date 2016
 * \date 2023
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
#pragma once

#include <ctime>
#include <string>
#include <ipfixprobe/storagePlugin.hpp>
#include <optional>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/telemetry-utils.hpp>
#include <unordered_map>
#include "fragmentationCache/fragmentationCache.hpp"
#include "cacheOptParser.hpp"
#include "cacheRowSpan.hpp"
#include "flowKey.hpp"
#include "flowRecord.hpp"
#include "cacheStats.hpp"
#include <ipfixprobe/cttConfig.hpp>

namespace ipxp {

class NHTFlowCache : protected TelemetryUtils, public StoragePlugin
{
public:

   /**
     * @brief Constructor 
     * @param vlan_is_flow_key If true, VLAN ID is included in the flow key, not included otherwise.
     */
   NHTFlowCache(bool vlan_is_flow_key = true);

   /**
     * @brief Constructor
     * @param params Parameters for the cache.
     * @param queue Pointer to the ring buffer
     */
   NHTFlowCache(const std::string& params, ipx_ring_t* queue);
   
   ~NHTFlowCache() override;
   
   /**
     * @brief Get the options parser for the cache.
     * @return Pointer to the options parser.
     */
   OptionsParser * get_parser() const override;

   /**
     * @brief Get the name of the cache.
     * @return Name of the cache.
     */
   std::string get_name() const noexcept override;
   
   /**
     * @brief Insert a packet into the cache.
     * @param packet The packet to be inserted.
     * @return 0 on success, negative value on error.
     */
   int put_pkt(Packet& packet) override;

   /**
     * @brief Export expired flows.
     * @param now Current time in seconds since the epoch.
     */
   void export_expired(time_t now) override;

   /**
     * @brief Set and configure the telemetry directory where cache stats will be stored.
     */
   void set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir) override;

   /**
     * @brief Finish the cache, export all remaining flows.
     */
   void finish() override;

protected:
   struct FlowSearch {
      CacheRowSpan cache_row; // Cache row where the flow to which packet belongs must be stored
      std::optional<size_t> flow_index; // Index of the flow in the table, if found
      size_t hash_value; // Hash value of the flow

      /**  
        * @brief Check if the flow was found in the cache.
        * @return True if the flow was found, false otherwise.
        */
      bool flow_found() const noexcept {
         return flow_index.has_value();
      }
   };

   uint32_t m_cache_size{0};
   uint32_t m_line_size{0};
   uint32_t m_line_mask{0};
   uint32_t m_new_flow_insert_index{0};
   uint32_t m_queue_size{0};
   uint32_t m_queue_index{0};
   uint32_t m_last_exported_on_timeout_index{0};

   uint32_t m_active_timeout{0};
   uint32_t m_inactive_timeout{0};
   bool m_split_biflow{false};
   bool m_enable_fragmentation_cache{true};
   std::unique_ptr<FlowRecord*[]> m_flow_table;
   std::unique_ptr<FlowRecord[]> m_flows;

   FragmentationCache m_fragmentation_cache{0,0};
   FlowEndReasonStats m_flow_end_reason_stats = {};
   FlowRecordStats m_flow_record_stats = {};
   FlowCacheStats m_cache_stats = {};

   void init(const char* params) override;
   void close() override;
   void set_queue(ipx_ring_t* queue) override;
   maybe_virtual void allocate_table();
   maybe_virtual telemetry::Dict get_cache_telemetry();
   maybe_virtual int update_flow(Packet& packet, size_t flow_index) noexcept;
   maybe_virtual void try_to_export(size_t flow_index, bool call_pre_export, int reason) noexcept;
   maybe_virtual void create_record(const Packet& packet, size_t flow_index, size_t hash_value) noexcept;
   maybe_virtual void export_flow(FlowRecord** flow, int reason);
   maybe_virtual size_t find_victim(CacheRowSpan& row) const noexcept;
   maybe_virtual void export_expired(const timeval& now);
   maybe_virtual void export_and_reuse_flow(size_t flow_index) noexcept;
   virtual void print_report() const;

   void try_to_fill_ports_to_fragmented_packet(Packet& packet);
   void flush(Packet &pkt, size_t flow_index, int return_flags);
   void update_flow_end_reason_stats(uint8_t reason);
   void update_flow_record_stats(uint64_t packets_count);
   void prefetch_export_expired() const;
   void get_parser_options(CacheOptParser& parser) noexcept;
   void push_to_export_queue(size_t flow_index) noexcept;
   void push_to_export_queue(FlowRecord*& flow) noexcept;
   std::pair<NHTFlowCache::FlowSearch, bool>
   find_flow_index(const FlowKey& key, bool swapped) noexcept;
   FlowSearch find_row(const FlowKey& key) noexcept;
   bool try_to_export_on_inactive_timeout(size_t flow_index, const timeval& now) noexcept;
   bool try_to_export_on_active_timeout(size_t flow_index, const timeval& now) noexcept;
   void export_flow(size_t flow_index, int reason);
   void export_flow(FlowRecord** flow);
   void export_flow(size_t flow_index);
   bool try_to_export_delayed_flow(const Packet& packet, size_t flow_index) noexcept;
   void try_to_export(size_t flow_index, bool call_pre_export) noexcept;
   void send_export_request_to_ctt(size_t ctt_flow_hash) noexcept;
   void try_to_add_flow_to_ctt(size_t flow_index) noexcept; 
   size_t get_empty_place(CacheRowSpan& row) noexcept;

   static uint8_t get_export_reason(const Flow &flow);

private:
   const bool m_vlan_is_flow_key{true};
};

}