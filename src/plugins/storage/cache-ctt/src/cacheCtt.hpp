/**
 * \file cache.hpp
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
#pragma once

#include "../../cache/src/cache.hpp"

#include <feta.hpp>
#include <unordered_map>

#include "cttController.hpp"
#include "flowRecordCtt.hpp"
#include "cttRemoveQueue.hpp"

namespace ipxp {

/**
 * \brief Extension of the NHTFlowCache class with CTT support
 */
class NHTFlowCacheCtt : public NHTFlowCache {
public:
   
   /**
      * \brief Constructor
      * \param params Parameters for the cache
      * \param queue Pointer to the ring buffer
      */
   NHTFlowCacheCtt(const std::string& params, ipx_ring_t* queue);

   ~NHTFlowCacheCtt() override;

   /**
   * \brief Get the options parser for the cache
   * \return Pointer to the options parser
   */
   OptionsParser * get_parser() const override;

   /** 
      * \brief Get the name of the cache
      * \return Name of the cache
      */
   std::string get_name() const noexcept override;

   /** 
      * \brief Insert a packet into the cache
      * \param packet Packet to be inserted
      * \return 0 on success, -1 on error
      */
   int put_pkt(Packet& packet) override;

private:
   /**
    * \brief Structure to search ipfixprobe flow records based on CTT export data.
    */
   struct CttFlowSearch{
      FlowRecordCtt** flow_record; /**< Pointer to the flow record */
      bool is_from_remove_queue; /**< True if the flow record is from the remove queue, false if from the main ipfixprobe memory */
   };

   void init(const char* params) override;
   void export_expired(const timeval& now) override;
   void process_external_export(const Packet& pkt) noexcept;
   void flush_ctt(const timeval now) noexcept;
   void export_flow(FlowRecord** flow, int reason) override;

   void finish() override;
   void create_record(const Packet& packet, size_t flow_index, size_t hash_value) noexcept override;
   int update_flow(Packet& packet, size_t flow_index) noexcept override;
   void try_to_export(size_t flow_index, bool call_pre_export, int reason) noexcept override;
   bool requires_input() const override;
   void init_ctt(const CttConfig& ctt_config) override;
   void allocate_table() override;
   void print_report() const override;
   void close() override;
   size_t find_victim(CacheRowSpan& row) const noexcept override;
   void print_flush_progress(size_t current_pos) const noexcept;
   void export_and_reuse_flow(size_t flow_index) noexcept override;
   void set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir) override;

   std::optional<feta::OffloadMode> get_offload_mode(size_t flow_index) noexcept;
   std::optional<CttFlowSearch> find_flow_from_ctt_export(const feta::CttExportPkt& export_data) noexcept;
   void offload_flow_to_ctt(size_t flow_index, feta::OffloadMode offload_mode) noexcept;
   void try_to_add_flow_to_ctt(size_t flow_index) noexcept;
   void send_export_request_to_ctt(size_t ctt_flow_hash) noexcept;
   void update_advanced_ctt_export_stats(const feta::CttExportPkt& export_data) noexcept;
   telemetry::Dict get_libctt_telemetry() noexcept;
   telemetry::Dict get_ctt_telemetry() noexcept;

   CttStats m_ctt_stats = {};
   uint8_t m_dma_channel{0};
   std::optional<CttController> m_ctt_controller;
   size_t m_prefinish_index{0};
   bool m_ctt_flow_seen{false};
   size_t m_ctt_flows_flushed{0};
   bool m_table_flushed{false};
   std::optional<feta::OffloadMode> m_offload_mode;
   FlowRecordCtt** m_flow_table{nullptr};
   std::unique_ptr<FlowRecordCtt[]> m_flows;
   CttRemoveQueue m_ctt_remove_queue;
   size_t m_ctt_remove_queue_size{0};
   size_t m_offload_threshold{std::numeric_limits<size_t>::max()};
};
}