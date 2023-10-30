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

#include <memory>
#include <optional>
#include <string>

#include <array>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

template<uint16_t IPSize>
struct __attribute__((packed)) flow_key {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t ip_version;
    std::array<uint8_t, IPSize> src_ip;
    std::array<uint8_t, IPSize> dst_ip;
    uint16_t vlan_id;
    flow_key<IPSize>& operator=(const Packet& pkt) noexcept;
    flow_key<IPSize>& save_reversed(const Packet& pkt) noexcept;
};
struct __attribute__((packed)) flow_key_v4 : public flow_key<4> {
    flow_key_v4& operator=(const Packet& pkt) noexcept;
    flow_key_v4& save_reversed(const Packet& pkt) noexcept;
};
struct __attribute__((packed)) flow_key_v6 : public flow_key<16> {
    flow_key_v6& operator=(const Packet& pkt) noexcept;
    flow_key_v6& save_reversed(const Packet& pkt) noexcept;
};

#ifdef FLOW_CACHE_STATS
static const constexpr bool PRINT_FLOW_CACHE_STATS = true;
#else
static const constexpr bool PRINT_FLOW_CACHE_STATS = false;
#endif /* FLOW_CACHE_STATS */

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

class CacheOptParser : public OptionsParser {
public:
    uint32_t m_cache_size;
    uint32_t m_line_size;
    uint32_t m_active = 300;
    uint32_t m_inactive = 30;
    bool m_split_biflow;

    CacheOptParser()
        : OptionsParser("cache", "Storage plugin implemented as a hash table")
        , m_cache_size(1 << DEFAULT_FLOW_CACHE_SIZE)
        , m_line_size(1 << DEFAULT_FLOW_LINE_SIZE)
        , m_split_biflow(false)
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
                m_split_biflow = true;
                return true;
            },
            OptionFlags::NoArgument);
    }
};

class FlowRecord {
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

template<bool NEED_FLOW_CACHE_STATS = false>
class NHTFlowCache : public StoragePlugin {
public:
    NHTFlowCache();
    ~NHTFlowCache() override;
    void init(const char* params) override;
    void close() override;
    void set_queue(ipx_ring_t* queue) override;
    OptionsParser* get_parser() const override { return new CacheOptParser(); }
    std::string get_name() const override { return "cache"; }

    int put_pkt(Packet& pkt) override;
    void export_expired(time_t ts) override;

protected:
    uint32_t m_cache_size;
    uint32_t m_line_size;
    uint32_t m_line_mask;
    uint32_t m_line_new_idx;
    uint32_t m_qsize;
    uint32_t m_qidx;
    uint32_t m_timeout_idx;
    uint32_t m_active;
    uint32_t m_inactive;
    bool m_split_biflow;
    uint8_t m_keylen;
    char m_key[max<size_t>(sizeof(flow_key_v4), sizeof(flow_key_v6))];
    char m_key_inv[max<size_t>(sizeof(flow_key_v4), sizeof(flow_key_v6))];
    std::unique_ptr<FlowRecord*[]> m_flow_table;
    std::unique_ptr<FlowRecord[]> m_flow_records;

    virtual void flush(Packet& pkt, size_t flow_index, int ret, bool source_flow);
    bool create_hash_key(const Packet& pkt) noexcept;
    void export_flow(size_t index);
    static uint8_t get_export_reason(Flow& flow);
    void finish() override;
    void get_opts_from_parser(const CacheOptParser& parser);

    std::pair<bool, uint32_t>
    find_existing_record(uint32_t begin_line, uint32_t end_line, uint64_t hashval) const noexcept;
    virtual uint32_t
    enhance_existing_flow_record(uint32_t flow_index, uint32_t line_index) noexcept;
    std::pair<bool, uint32_t>
    find_empty_place(uint32_t begin_line, uint32_t end_line) const noexcept;
    virtual uint32_t put_into_free_place(
        uint32_t flow_index,
        bool empty_place_found,
        uint32_t begin_line,
        uint32_t end_line) noexcept;

    bool process_last_tcp_packet(Packet& pkt, uint32_t flow_index) noexcept;
    virtual bool create_new_flow(uint32_t flow_index, Packet& pkt, uint64_t hashval) noexcept;
    virtual bool flush_and_update_flow(uint32_t flow_index, Packet& pkt) noexcept;
    virtual void prepare_and_export(uint32_t flow_index) noexcept;
    virtual void prepare_and_export(uint32_t flow_index, uint32_t reason) noexcept;

    static void test_attributes();
};
template<>
class NHTFlowCache<true> : public NHTFlowCache<false> {
    uint64_t m_empty;
    uint64_t m_not_empty;
    uint64_t m_hits;
    uint64_t m_expired;
    uint64_t m_flushed;
    uint64_t m_lookups;
    uint64_t m_lookups2;

    void init(const char* params) override;
    ~NHTFlowCache() override;

    uint32_t
    enhance_existing_flow_record(uint32_t flow_index, uint32_t line_index) noexcept override;
    uint32_t put_into_free_place(
        uint32_t flow_index,
        bool empty_place_found,
        uint32_t begin_line,
        uint32_t end_line) noexcept override;
    bool create_new_flow(uint32_t flow_index, Packet& pkt, uint64_t hashval) noexcept override;
    void flush(Packet& pkt, size_t flow_index, int ret, bool source_flow) override;
    void prepare_and_export(uint32_t flow_index) noexcept override;
    void prepare_and_export(uint32_t flow_index, uint32_t reason) noexcept override;
    void print_report() const noexcept;

};

} // namespace ipxp
#endif /* IPXP_STORAGE_CACHE_HPP */
