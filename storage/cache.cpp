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
#include <cstring>
#include <iostream>
#include <sys/time.h>
#include <chrono>
#include "cache.hpp"
#include "xxhash.h"
#include <fstream>
#include <iomanip>
#include <ipfixprobe/ring.h>

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin() noexcept
{
    static PluginRecord rec = PluginRecord("cache", []() { return new NHTFlowCache<PRINT_FLOW_CACHE_STATS>(); });
    register_plugin(&rec);
}

template<uint16_t IPSize>
flow_key<IPSize>& flow_key<IPSize>::operator=(const Packet& pkt) noexcept
{
    proto = pkt.ip_proto;
    src_port = pkt.src_port;
    dst_port = pkt.dst_port;
    vlan_id = pkt.vlan_id;
    return *this;
}

template<uint16_t IPSize>
flow_key<IPSize>& flow_key<IPSize>::save_reversed(const Packet& pkt) noexcept
{
    *this = pkt;
    src_port = pkt.dst_port;
    dst_port = pkt.src_port;
    return *this;
}

flow_key_v4& flow_key_v4::operator=(const Packet& pkt) noexcept
{
    flow_key::operator=(pkt);
    ip_version = IP::v4;
    memcpy(src_ip.data(), &pkt.src_ip.v4, 4);
    memcpy(dst_ip.data(), &pkt.dst_ip.v4, 4);
    return *this;
}

flow_key_v4& flow_key_v4::save_reversed(const Packet& pkt) noexcept
{
    flow_key::save_reversed(pkt);
    ip_version = IP::v4;
    memcpy(src_ip.data(), &pkt.dst_ip.v4, 4);
    memcpy(dst_ip.data(), &pkt.src_ip.v4, 4);
    return *this;
}

flow_key_v6& flow_key_v6::operator=(const Packet& pkt) noexcept
{
    flow_key::operator=(pkt);
    ip_version = IP::v6;
    memcpy(src_ip.data(), pkt.src_ip.v6, 16);
    memcpy(dst_ip.data(), pkt.dst_ip.v6, 16);
    return *this;
}

flow_key_v6& flow_key_v6::save_reversed(const Packet& pkt) noexcept
{
    flow_key::save_reversed(pkt);
    ip_version = IP::v6;
    memcpy(src_ip.data(), pkt.dst_ip.v6, 16);
    memcpy(dst_ip.data(), pkt.src_ip.v6, 16);
    return *this;
}

FlowRecord::FlowRecord()
{
    erase();
}

FlowRecord::~FlowRecord()
{
    erase();
}

void FlowRecord::erase()
{
    m_flow.remove_extensions();
    m_hash = 0;
    memset(&m_flow.time_first, 0, sizeof(m_flow.time_first));
    memset(&m_flow.time_last, 0, sizeof(m_flow.time_last));
    m_flow.ip_version = 0;
    m_flow.ip_proto = 0;
    memset(&m_flow.src_ip, 0, sizeof(m_flow.src_ip));
    memset(&m_flow.dst_ip, 0, sizeof(m_flow.dst_ip));
    m_flow.src_port = 0;
    m_flow.dst_port = 0;
    m_flow.src_packets = 0;
    m_flow.dst_packets = 0;
    m_flow.src_bytes = 0;
    m_flow.dst_bytes = 0;
    m_flow.src_tcp_flags = 0;
    m_flow.dst_tcp_flags = 0;
}
void FlowRecord::reuse()
{
    m_flow.remove_extensions();
    m_flow.time_first = m_flow.time_last;
    m_flow.src_packets = 0;
    m_flow.dst_packets = 0;
    m_flow.src_bytes = 0;
    m_flow.dst_bytes = 0;
    m_flow.src_tcp_flags = 0;
    m_flow.dst_tcp_flags = 0;
}

inline __attribute__((always_inline)) bool FlowRecord::is_empty() const
{
    return m_hash == 0;
}

inline __attribute__((always_inline)) bool FlowRecord::belongs(uint64_t hash) const
{
    return hash == m_hash;
}

void FlowRecord::create(const Packet& pkt, uint64_t hash)
{
    m_flow.src_packets = 1;

    m_hash = hash;

    m_flow.time_first = pkt.ts;
    m_flow.time_last = pkt.ts;
    m_flow.flow_hash = hash;

    memcpy(m_flow.src_mac, pkt.src_mac, 6);
    memcpy(m_flow.dst_mac, pkt.dst_mac, 6);

    if (pkt.ip_version == IP::v4) {
        m_flow.ip_version = pkt.ip_version;
        m_flow.ip_proto = pkt.ip_proto;
        m_flow.src_ip.v4 = pkt.src_ip.v4;
        m_flow.dst_ip.v4 = pkt.dst_ip.v4;
        m_flow.src_bytes = pkt.ip_len;
    } else if (pkt.ip_version == IP::v6) {
        m_flow.ip_version = pkt.ip_version;
        m_flow.ip_proto = pkt.ip_proto;
        memcpy(m_flow.src_ip.v6, pkt.src_ip.v6, 16);
        memcpy(m_flow.dst_ip.v6, pkt.dst_ip.v6, 16);
        m_flow.src_bytes = pkt.ip_len;
    }

    if (pkt.ip_proto == IPPROTO_TCP) {
        m_flow.src_port = pkt.src_port;
        m_flow.dst_port = pkt.dst_port;
        m_flow.src_tcp_flags = pkt.tcp_flags;
    } else if (pkt.ip_proto == IPPROTO_UDP) {
        m_flow.src_port = pkt.src_port;
        m_flow.dst_port = pkt.dst_port;
    } else if (pkt.ip_proto == IPPROTO_ICMP || pkt.ip_proto == IPPROTO_ICMPV6) {
        m_flow.src_port = pkt.src_port;
        m_flow.dst_port = pkt.dst_port;
    }
}

void FlowRecord::update(const Packet& pkt, bool src)
{
    m_flow.time_last = pkt.ts;
    if (src) {
        m_flow.src_packets++;
        m_flow.src_bytes += pkt.ip_len;

        if (pkt.ip_proto == IPPROTO_TCP) {
            m_flow.src_tcp_flags |= pkt.tcp_flags;
        }
    } else {
        m_flow.dst_packets++;
        m_flow.dst_bytes += pkt.ip_len;

        if (pkt.ip_proto == IPPROTO_TCP) {
            m_flow.dst_tcp_flags |= pkt.tcp_flags;
        }
    }
}

template<bool NEED_FLOW_CACHE_STATS>
NHTFlowCache<NEED_FLOW_CACHE_STATS>::NHTFlowCache()
    : m_cache_size(0)
    , m_line_size(0)
    , m_line_mask(0)
    , m_line_new_idx(0)
    , m_qsize(0)
    , m_qidx(0)
    , m_timeout_idx(0)
    , m_active(0)
    , m_inactive(0)
    , m_split_biflow(false)
    , m_keylen(0)
    , m_key()
    , m_key_inv()
    , m_flow_table(nullptr)
    , m_flow_records(nullptr)
{
    test_attributes();
}

template<bool NEED_FLOW_CACHE_STATS>
NHTFlowCache<NEED_FLOW_CACHE_STATS>::~NHTFlowCache()
{
    NHTFlowCache::close();
}

NHTFlowCache<true>::~NHTFlowCache()
{
    if (m_hits)
        print_report();
    NHTFlowCache::close();
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::test_attributes()
{
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
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::get_opts_from_parser(const CacheOptParser& parser)
{
    m_cache_size = parser.m_cache_size;
    m_line_size = parser.m_line_size;
    m_active = parser.m_active;
    m_inactive = parser.m_inactive;
    m_split_biflow = parser.m_split_biflow;
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::init(const char* params)
{
    CacheOptParser parser;
    try {
        parser.parse(params);
    } catch (ParserError& e) {
        throw PluginError(e.what());
    }

    get_opts_from_parser(parser);
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
        m_flow_table = std::unique_ptr<FlowRecord*[]>(new FlowRecord*[m_cache_size + m_qsize]);
        m_flow_records = std::unique_ptr<FlowRecord[]>(new FlowRecord[m_cache_size + m_qsize]);
        for (decltype(m_cache_size + m_qsize) i = 0; i < m_cache_size + m_qsize; i++) {
            m_flow_table[i] = &m_flow_records[i];
        }
    } catch (std::bad_alloc& e) {
        throw PluginError("not enough memory for flow cache allocation");
    }
}
void NHTFlowCache<true>::init(const char* params)
{
    NHTFlowCache<false>::init(params);
    m_empty = 0;
    m_not_empty = 0;
    m_hits = 0;
    m_expired = 0;
    m_flushed = 0;
    m_lookups = 0;
    m_lookups2 = 0;
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::close()
{
    m_flow_records.reset();
    m_flow_table.reset();
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::set_queue(ipx_ring_t* queue)
{
    m_export_queue = queue;
    m_qsize = ipx_ring_size(queue);
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::export_flow(size_t index)
{
    ipx_ring_push(m_export_queue, &m_flow_table[index]->m_flow);
    std::swap(m_flow_table[index], m_flow_table[m_cache_size + m_qidx]);
    m_flow_table[index]->erase();
    m_qidx = (m_qidx + 1) % m_qsize;
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::finish()
{
    for (decltype(m_cache_size) i = 0; i < m_cache_size; i++)
        if (!m_flow_table[i]->is_empty())
            prepare_and_export(i, FLOW_END_FORCED);
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::prepare_and_export(uint32_t flow_index) noexcept
{
    plugins_pre_export(m_flow_table[flow_index]->m_flow);
    m_flow_table[flow_index]->m_flow.end_reason
        = get_export_reason(m_flow_table[flow_index]->m_flow);
    export_flow(flow_index);
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::prepare_and_export(
    uint32_t flow_index,
    uint32_t reason) noexcept
{
    plugins_pre_export(m_flow_table[flow_index]->m_flow);
    m_flow_table[flow_index]->m_flow.end_reason = reason;
    export_flow(flow_index);
}

void NHTFlowCache<true>::prepare_and_export(uint32_t flow_index) noexcept
{
    NHTFlowCache<false>::prepare_and_export(flow_index);
    m_expired++;
}

void NHTFlowCache<true>::prepare_and_export(uint32_t flow_index, uint32_t reason) noexcept
{
    NHTFlowCache<false>::prepare_and_export(flow_index, reason);
    m_expired++;
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::flush(
    Packet& pkt,
    size_t flow_index,
    int ret,
    bool source_flow)
{
    if (ret == FLOW_FLUSH_WITH_REINSERT) {
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
    }
}

void NHTFlowCache<true>::flush(Packet& pkt, size_t flow_index, int ret, bool source_flow)
{
    m_flushed++;
    NHTFlowCache<false>::flush(pkt, flow_index, ret, source_flow);
}

template<bool NEED_FLOW_CACHE_STATS>
std::pair<bool, uint32_t> NHTFlowCache<NEED_FLOW_CACHE_STATS>::find_existing_record(
    uint32_t begin_line,
    uint32_t end_line,
    uint64_t hashval) const noexcept
{
    for (uint32_t flow_index = begin_line; flow_index < end_line; flow_index++) {
        if (m_flow_table[flow_index]->belongs(hashval))
            return {true, flow_index};
    }
    return {false, 0};
}

template<bool NEED_FLOW_CACHE_STATS>
uint32_t NHTFlowCache<NEED_FLOW_CACHE_STATS>::enhance_existing_flow_record(
    uint32_t flow_index,
    uint32_t line_index) noexcept
{
    auto flow = m_flow_table[flow_index];
    for (decltype(flow_index) j = flow_index; j > line_index; j--) {
        m_flow_table[j] = m_flow_table[j - 1];
    }
    m_flow_table[line_index] = flow;
    return line_index;
}

uint32_t
NHTFlowCache<true>::enhance_existing_flow_record(uint32_t flow_index, uint32_t line_index) noexcept
{
    m_lookups += (flow_index - line_index + 1);
    m_lookups2 += (flow_index - line_index + 1) * (flow_index - line_index + 1);
    m_hits++;
    return NHTFlowCache<false>::enhance_existing_flow_record(flow_index, line_index);
}

template<bool NEED_FLOW_CACHE_STATS>
std::pair<bool, uint32_t> NHTFlowCache<NEED_FLOW_CACHE_STATS>::find_empty_place(
    uint32_t begin_line,
    uint32_t end_line) const noexcept
{
    for (uint32_t flow_index = begin_line; flow_index < end_line; flow_index++) {
        if (m_flow_table[flow_index]->is_empty())
            return {true, flow_index};
    }
    return {false, 0};
}

template<bool NEED_FLOW_CACHE_STATS>
uint32_t NHTFlowCache<NEED_FLOW_CACHE_STATS>::put_into_free_place(
    uint32_t flow_index,
    bool empty_place_found,
    uint32_t begin_line,
    uint32_t end_line) noexcept
{
    /* If free place was not found (flow line is full), find
     * record which will be replaced by new record. */
    if (empty_place_found)
        return flow_index;
    prepare_and_export(end_line - 1, FLOW_END_NO_RES);
    uint32_t flow_new_index = begin_line + m_line_new_idx;

    auto flow = m_flow_table[flow_index];
    for (decltype(flow_index) j = flow_index; j > flow_new_index; j--)
        m_flow_table[j] = m_flow_table[j - 1];
    m_flow_table[flow_new_index] = flow;
    return flow_new_index;
}

uint32_t NHTFlowCache<true>::put_into_free_place(
    uint32_t flow_index,
    bool empty_place_found,
    uint32_t begin_line,
    uint32_t end_line) noexcept
{
    if (empty_place_found)
        m_empty++;
    else
        m_not_empty++;
    return NHTFlowCache<false>::put_into_free_place(
        flow_index,
        empty_place_found,
        begin_line,
        end_line);
}

template<bool NEED_FLOW_CACHE_STATS>
bool NHTFlowCache<NEED_FLOW_CACHE_STATS>::process_last_tcp_packet(
    Packet& pkt,
    uint32_t flow_index) noexcept
{
    uint8_t flw_flags = pkt.source_pkt ? m_flow_table[flow_index]->m_flow.src_tcp_flags
                                       : m_flow_table[flow_index]->m_flow.dst_tcp_flags;
    if ((pkt.tcp_flags & 0x02) && (flw_flags & (0x01 | 0x04))) {
        // Flows with FIN or RST TCP flags are exported when new SYN packet arrives
        m_flow_table[flow_index]->m_flow.end_reason = FLOW_END_EOF;
        export_flow(flow_index);
        put_pkt(pkt);
        return true;
    }
    return false;
}

template<bool NEED_FLOW_CACHE_STATS>
bool NHTFlowCache<NEED_FLOW_CACHE_STATS>::create_new_flow(
    uint32_t flow_index,
    Packet& pkt,
    uint64_t hashval) noexcept
{
    m_flow_table[flow_index]->create(pkt, hashval);
    auto ret = plugins_post_create(m_flow_table[flow_index]->m_flow, pkt);
    if (ret & FLOW_FLUSH) {
        export_flow(flow_index);
        return true;
    }
    return false;
}
bool NHTFlowCache<true>::create_new_flow(
    uint32_t flow_index,
    Packet& pkt,
    uint64_t hashval) noexcept
{
    if (NHTFlowCache<false>::create_new_flow(flow_index, pkt, hashval))
        m_flushed++;
    return true;
}

template<bool NEED_FLOW_CACHE_STATS>
bool NHTFlowCache<NEED_FLOW_CACHE_STATS>::flush_and_update_flow(
    uint32_t flow_index,
    Packet& pkt) noexcept
{
    auto ret = plugins_pre_update(m_flow_table[flow_index]->m_flow, pkt);
    if (ret & FLOW_FLUSH) {
        flush(pkt, flow_index, ret, pkt.source_pkt);
        return true;
    } else {
        m_flow_table[flow_index]->update(pkt, pkt.source_pkt);
        ret = plugins_post_update(m_flow_table[flow_index]->m_flow, pkt);
        if (ret & FLOW_FLUSH) {
            flush(pkt, flow_index, ret, pkt.source_pkt);
            return true;
        }
    }
    return false;
}

template<bool NEED_FLOW_CACHE_STATS>
int NHTFlowCache<NEED_FLOW_CACHE_STATS>::put_pkt(Packet& pkt)
{
    plugins_pre_create(pkt);

    if (!create_hash_key(pkt))
        return 0;
    /* Calculates hash value from key created before. */
    uint64_t hashval = XXH64(m_key, m_keylen, 0);
    bool source_flow = true;

    /* Get index of flow line. */
    uint32_t line_index = hashval & m_line_mask;
    uint32_t next_line = line_index + m_line_size;

    auto res = find_existing_record(line_index, next_line, hashval);
    bool found = res.first;
    uint32_t flow_index = res.second;

    /* Find inversed flow. */
    if (!found && !m_split_biflow) {
        uint64_t hashval_inv = XXH64(m_key_inv, m_keylen, 0);
        uint64_t line_index_inv = hashval_inv & m_line_mask;
        uint64_t next_line_inv = line_index_inv + m_line_size;
        res = find_existing_record(line_index_inv, next_line_inv, hashval_inv);
        found = res.first;
        if (found) {
            flow_index = res.second;
            source_flow = false;
            hashval = hashval_inv;
            line_index = line_index_inv;
        }
    }

    /* Existing flow record was found, put flow record at the first index of flow line. */
    if (found) {
        flow_index = enhance_existing_flow_record(flow_index, line_index);
        /* Existing flow record was not found. Find free place in flow line or replace some existing
         * record. */
    } else {
        res = find_empty_place(line_index, next_line);
        bool empty_place_found = res.first;
        flow_index = res.second;
        flow_index = put_into_free_place(flow_index, empty_place_found, line_index, next_line);
    }

    pkt.source_pkt = source_flow;
    if (process_last_tcp_packet(pkt, flow_index))
        return 0;

    if (m_flow_table[flow_index]->is_empty())
        create_new_flow(flow_index, pkt, hashval);
    else {
        /* Check if flow record is expired (inactive timeout). */
        if (pkt.ts.tv_sec - m_flow_table[flow_index]->m_flow.time_last.tv_sec >= m_inactive) {
            prepare_and_export(flow_index);
            return put_pkt(pkt);
        }
        /* Check if flow record is expired (active timeout). */
        if (pkt.ts.tv_sec - m_flow_table[flow_index]->m_flow.time_first.tv_sec >= m_active) {
            prepare_and_export(flow_index, FLOW_END_ACTIVE);
            return put_pkt(pkt);
        }
        if (flush_and_update_flow(flow_index, pkt))
            return 0;
    }
    export_expired(pkt.ts.tv_sec);
    return 0;
}


    int NHTFlowCache<true>::put_pkt(Packet& pkt){
        auto start = std::chrono::high_resolution_clock::now();
        auto res = NHTFlowCache<false>::put_pkt(pkt);
        m_put_time += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
        return res;
    }

template<bool NEED_FLOW_CACHE_STATS>
uint8_t NHTFlowCache<NEED_FLOW_CACHE_STATS>::get_export_reason(Flow& flow)
{
    if ((flow.src_tcp_flags | flow.dst_tcp_flags) & (0x01 | 0x04)) {
        // When FIN or RST is set, TCP connection ended naturally
        return FLOW_END_EOF;
    } else {
        return FLOW_END_INACTIVE;
    }
}

template<bool NEED_FLOW_CACHE_STATS>
void NHTFlowCache<NEED_FLOW_CACHE_STATS>::export_expired(time_t ts)
{
    for (decltype(m_timeout_idx) i = m_timeout_idx; i < m_timeout_idx + m_line_new_idx; i++) {
        if (!m_flow_table[i]->is_empty()
            && ts - m_flow_table[i]->m_flow.time_last.tv_sec >= m_inactive) {
            prepare_and_export(i);
        }
    }
    m_timeout_idx = (m_timeout_idx + m_line_new_idx) & (m_cache_size - 1);
}
// saves key value and key length into attributes NHTFlowCache::keyand NHTFlowCache::m_keylen
template<bool NEED_FLOW_CACHE_STATS>
bool NHTFlowCache<NEED_FLOW_CACHE_STATS>::create_hash_key(const Packet& pkt) noexcept
{
    if (pkt.ip_version == IP::v4) {
        auto key_v4 = reinterpret_cast<struct flow_key_v4*>(m_key);
        auto key_v4_inv = reinterpret_cast<struct flow_key_v4*>(m_key_inv);

        *key_v4 = pkt;
        key_v4_inv->save_reversed(pkt);
        m_keylen = sizeof(flow_key_v4);
        return true;
    }
    if (pkt.ip_version == IP::v6) {
        auto key_v6 = reinterpret_cast<struct flow_key_v6*>(m_key);
        auto key_v6_inv = reinterpret_cast<struct flow_key_v6*>(m_key_inv);

        *key_v6 = pkt;
        key_v6_inv->save_reversed(pkt);
        m_keylen = sizeof(flow_key_v6);
        return true;
    }
    return false;
}

void NHTFlowCache<true>::print_report() const noexcept
{
    float tmp = float(m_lookups) / m_hits;
    std::cout << "Hits: " << m_hits << std::endl;
    std::cout << "Empty: " << m_empty << std::endl;
    std::cout << "Not empty: " << m_not_empty << std::endl;
    std::cout << "Expired: " << m_expired << std::endl;
    std::cout << "Flushed: " << m_flushed << std::endl;
    std::cout << "Average Lookup:  " << tmp << std::endl;
    std::cout << "Variance Lookup: " << float(m_lookups2) / m_hits - tmp * tmp << std::endl;
    std::cout << "Spent in put_pkt: " << m_put_time << " us" << std::endl;
}

} // namespace ipxp
