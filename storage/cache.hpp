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
#ifndef IPXP_STORAGE_CACHE_HPP
#define IPXP_STORAGE_CACHE_HPP

#include "cacheoptparser.hpp"
#include "cachestatistics.hpp"
#include "flowendreason.hpp"
#include "flowkeyv4.hpp"
#include "flowkeyv6.hpp"
#include "flowrecord.hpp"
#include <array>
#include <chrono>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/utils.hpp>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <thread>
#include "fragmentationCache/fragmentationCache.hpp"

namespace ipxp {

using namespace std::chrono_literals;
class NHTFlowCache : public StoragePlugin {
public:
    NHTFlowCache();
    ~NHTFlowCache() override;
    void init(const char* params) override;
    void set_queue(ipx_ring_t* queue) override;
    OptionsParser* get_parser() const;
    std::string get_name() const noexcept;
    int put_pkt(Packet& pkt) override;
    void export_expired(time_t ts) override;
    void print_report() const noexcept;
    void set_hash_function(std::function<uint64_t(const uint8_t* data,uint32_t len)> function) noexcept;

private:
    uint32_t m_cache_size; ///< Maximal count of records in cache
    uint32_t m_line_size; ///< Maximal count of records in one row
    uint32_t m_line_mask; ///< Line mask xored with flow index returns start of the row
    uint32_t m_line_new_idx; ///< Insert position of new flow, if row has no empty space
    uint32_t m_qsize; ///< Export queue size
    uint32_t m_qidx; ///< Next position in export queue that will be exported
    uint32_t m_timeout_idx; ///< Index of the row where expired flow will be exported
    uint32_t m_active; ///< Active timeout
    uint32_t m_inactive; ///< Inactive timeout
    bool m_split_biflow; ///< If true, request and response packets between same ips will be counted
                         ///< belonging to different flows
    bool m_enable_fragmentation_cache; ///< If true, fragmentation cache will try to complete port
                                       ///< information for fragmented packet
    std::variant<FlowKeyV4, FlowKeyV6> m_key; ///< Key values of processed flow
    std::variant<FlowKeyV4, FlowKeyV6> m_key_inv; ///< Key values of processed flow with swapped
                                                  ///< source and destination addresses and ports
    std::vector<FlowRecord*>
        m_flow_table; ///< Pointers to flow records used for faster flow reorder operations
    std::vector<FlowRecord> m_flow_records; ///< Main memory of the cache
    CacheStatistics
        m_statistics; ///< Total statistics about cache efficiency from the program start
    CacheStatistics m_last_statistics; ///< Cache statistics for last
                                       ///< m_periodic_statistics_sleep_time amount of time
    bool m_exit; ///< Used for stopping background statistics thread
    std::chrono::duration<double>
        m_periodic_statistics_sleep_time; ///< Amount of time in which periodic statistics must
                                          ///< reset
    std::unique_ptr<std::thread> m_statistics_thread; ///< Pointer to periodic statistics thread
    FragmentationCache
        m_fragmentation_cache; ///< Fragmentation cache used for completing packets ports
    std::function<uint64_t(const uint8_t*,uint32_t)> m_hash_function;

    void try_to_fill_ports_to_fragmented_packet(Packet& packet);
    void allocate_tables();
    void export_periodic_statistics(std::ostream& stream) noexcept;
    void flush(
        Packet& pkt,
        uint32_t flow_index,
        int ret,
        bool source_flow,
        FlowEndReason reason) noexcept;
    uint32_t free_place_in_full_line(uint32_t line_begin) noexcept;
    bool tcp_connection_reset(Packet& pkt, uint32_t flow_index) noexcept;
    void create_new_flow(uint32_t flow_index, Packet& pkt, uint64_t hashval) noexcept;
    bool update_flow(uint32_t flow_index, Packet& pkt) noexcept;
    uint32_t make_place_for_record(uint32_t line_index) noexcept;
    std::tuple<bool, uint32_t, uint64_t> find_flow_position(Packet& pkt) noexcept;
    int insert_pkt(Packet& pkt) noexcept;
    bool timeouts_expired(Packet& pkt, uint32_t flow_index) noexcept;
    bool create_hash_key(const Packet& pkt) noexcept;
    void export_flow(uint32_t index);
    static uint8_t get_export_reason(Flow& flow);
    void finish() override;
    void get_opts_from_parser(const CacheOptParser& parser);
    std::pair<bool, uint32_t> find_existing_record(uint64_t hashval) const noexcept;
    virtual uint32_t enhance_existing_flow_record(uint32_t flow_index) noexcept;
    std::pair<bool, uint32_t> find_empty_place(uint32_t begin_line) const noexcept;
    bool process_last_tcp_packet(Packet& pkt, uint32_t flow_index) noexcept;
    void prepare_and_export(uint32_t flow_index, FlowEndReason reason) noexcept;
    void cyclic_rotate_records(uint32_t begin, uint32_t end) noexcept;
    uint64_t hash(const uint8_t* data, uint32_t len) const noexcept;

    static bool has_tcp_eof_flags(const Flow& flow) noexcept;
    static void test_attributes();
};

} // namespace ipxp
#endif /* IPXP_STORAGE_CACHE_HPP */
