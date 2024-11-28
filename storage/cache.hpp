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
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/utils.hpp>
#include <ipfixprobe/telemetry-utils.hpp>

#include "fragmentationCache/fragmentationCache.hpp"

#ifdef WITH_CTT
#include <sys/time.h>
#include <ctt_async.hpp>
#include <ctt_factory.hpp>
#include <ctt_exceptions.hpp>
#include <ctt_modes.hpp>
#include <ctt.hpp>
#include <queue>
#include <tuple>
#endif /* WITH_CTT */

namespace ipxp {

#ifdef WITH_CTT

class CttController {
public:
    enum class OffloadMode : uint8_t {
        NO_OFFLOAD = 0x0,
        PACKET_OFFLOAD = 0x1,
        META_EXPORT = 0x2,
        PACKET_OFFLOAD_WITH_EXPORT = 0x3
    };
    enum class MetaType : uint8_t {
        FULL = 0x0,
        HALF = 0x1,
        TS_ONLY = 0x2,
        NO_META = 0x3
    };
    /**
     * @brief init the CTT.
     *
     * @param nfb_dev          The NFB device file (e.g., "/dev/nfb0").
     * @param ctt_comp_index   The index of the CTT component.
     */
    void init(const std::string& nfb_dev, unsigned ctt_comp_index) {
      m_commander = std::make_unique<ctt::AsyncCommander>(ctt::NfbParams{nfb_dev, ctt_comp_index});
      try {
        // Get UserInfo to determine key, state, and state_mask sizes
        ctt::UserInfo user_info = m_commander->get_user_info();
        key_size_bytes = (user_info.key_bit_width + 7) / 8;
        state_size_bytes = (user_info.state_bit_width + 7) / 8;
        state_mask_size_bytes = (user_info.state_mask_bit_width + 7) / 8;

        // Enable the CTT
        std::future<void> enable_future = m_commander->enable(true);
        enable_future.wait(); 
      }
      catch (const std::exception& e) {
         throw;
      }
    }

    /**
     * @brief Command: mark a flow for offload.
     *
     * @param flow_hash_ctt    The flow hash to be offloaded.
     */
    void create_record(uint64_t flow_hash_ctt, const struct timeval& timestamp_first);

    /**
     * @brief Command: export a flow from the CTT.
     *
     * @param flow_hash_ctt    The flow hash to be exported.
     */
    void export_record(uint64_t flow_hash_ctt);

private:
    std::unique_ptr<ctt::AsyncCommander> m_commander;
    size_t key_size_bytes;
    size_t state_size_bytes;
    size_t state_mask_size_bytes;

    /**
     * @brief Assembles the state vector from the given values.
     *
     * @param offload_mode     The offload mode.
     * @param meta_type        The metadata type.
     * @param timestamp_first  The first timestamp of the flow.
     * @return A byte vector representing the assembled state vector.
     */
    std::vector<std::byte> assemble_state(
        OffloadMode offload_mode, MetaType meta_type,
        const struct timeval& timestamp_first);
    
    /**
     * @brief Assembles the key vector from the given flow hash.
     *
     * @param flow_hash_ctt    The flow hash.
     * @return A byte vector representing the assembled key vector.
     */
    std::vector<std::byte> assemble_key(uint64_t flow_hash_ctt);
};
#endif /* WITH_CTT */

struct __attribute__((packed)) flow_key_v4_t {
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
};

#define MAX_KEY_LENGTH (max<size_t>(sizeof(flow_key_v4_t), sizeof(flow_key_v6_t)))

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

static const uint32_t DEFAULT_INACTIVE_TIMEOUT = 30;
static const uint32_t DEFAULT_ACTIVE_TIMEOUT = 300;

static_assert(std::is_unsigned<decltype(DEFAULT_FLOW_CACHE_SIZE)>(), "Static checks of default cache sizes won't properly work without unsigned type.");
static_assert(bitcount<decltype(DEFAULT_FLOW_CACHE_SIZE)>(-1) > DEFAULT_FLOW_CACHE_SIZE, "Flow cache size is too big to fit in variable!");
static_assert(bitcount<decltype(DEFAULT_FLOW_LINE_SIZE)>(-1) > DEFAULT_FLOW_LINE_SIZE, "Flow cache line size is too big to fit in variable!");

static_assert(DEFAULT_FLOW_LINE_SIZE >= 1, "Flow cache line size must be at least 1!");
static_assert(DEFAULT_FLOW_CACHE_SIZE >= DEFAULT_FLOW_LINE_SIZE, "Flow cache size must be at least cache line size!");

class CacheOptParser : public OptionsParser
{
public:
   uint32_t m_cache_size;
   uint32_t m_line_size;
   uint32_t m_active;
   uint32_t m_inactive;
   bool m_split_biflow;
   bool m_enable_fragmentation_cache;
   std::size_t m_frag_cache_size;
   time_t m_frag_cache_timeout;
   #ifdef WITH_CTT
   std::string m_dev;
   #endif /* WITH_CTT */

   CacheOptParser() : OptionsParser("cache", "Storage plugin implemented as a hash table"),
      m_cache_size(1 << DEFAULT_FLOW_CACHE_SIZE), m_line_size(1 << DEFAULT_FLOW_LINE_SIZE),
      m_active(DEFAULT_ACTIVE_TIMEOUT), m_inactive(DEFAULT_INACTIVE_TIMEOUT), m_split_biflow(false),
      m_enable_fragmentation_cache(true), m_frag_cache_size(10007), // Prime for better distribution in hash table
      m_frag_cache_timeout(3)
   {
      register_option("s", "size", "EXPONENT", "Cache size exponent to the power of two",
         [this](const char *arg){try {unsigned exp = str2num<decltype(exp)>(arg);
               if (exp < 4 || exp > 30) {
                  throw PluginError("Flow cache size must be between 4 and 30");
               }
               m_cache_size = static_cast<uint32_t>(1) << exp;
            } catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("l", "line", "EXPONENT", "Cache line size exponent to the power of two",
         [this](const char *arg){try {m_line_size = static_cast<uint32_t>(1) << str2num<decltype(m_line_size)>(arg);
               if (m_line_size < 1) {
                  throw PluginError("Flow cache line size must be at least 1");
               }
            } catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("a", "active", "TIME", "Active timeout in seconds",
         [this](const char *arg){try {m_active = str2num<decltype(m_active)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("i", "inactive", "TIME", "Inactive timeout in seconds",
         [this](const char *arg){try {m_inactive = str2num<decltype(m_inactive)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("S", "split", "", "Split biflows into uniflows",
         [this](const char *arg){ m_split_biflow = true; return true;}, OptionFlags::NoArgument);
      register_option("fe", "frag-enable", "true|false", "Enable/disable fragmentation cache. Enabled (true) by default.",
         [this](const char *arg){
            if (strcmp(arg, "true") == 0) {
               m_enable_fragmentation_cache = true;
            } else if (strcmp(arg, "false") == 0) {
               m_enable_fragmentation_cache = false;
            } else {
               return false;
            }
            return true;
         }, OptionFlags::RequiredArgument);
      register_option("fs", "frag-size", "size", "Size of fragmentation cache, must be at least 1. Default value is 10007.", [this](const char *arg) {
         try {
            m_frag_cache_size = str2num<decltype(m_frag_cache_size)>(arg);
         } catch(std::invalid_argument &e) {
            return false;
         }
         return m_frag_cache_size > 0;
      });
      register_option("ft", "frag-timeout", "TIME", "Timeout of fragments in fragmentation cache in seconds. Default value is 3.", [this](const char *arg) {
         try {
            m_frag_cache_timeout = str2num<decltype(m_frag_cache_timeout)>(arg);
         } catch(std::invalid_argument &e) {
            return false;
         }
         return true;
      });

      #ifdef WITH_CTT
      register_option("d", "dev", "DEV", "Device name",
         [this](const char *arg) {
            m_dev = arg;
            return true;
         },
         OptionFlags::RequiredArgument);
      #endif /* WITH_CTT */

   }
};

class alignas(64) FlowRecord
{
   uint64_t m_hash;

public:
   Flow m_flow;
   #ifdef WITH_CTT
      Flow m_delayed_flow;
      bool m_delayed_flow_waiting;
   #endif /* WITH_CTT */

   FlowRecord();
   ~FlowRecord();

   void erase();
   void reuse();

   inline bool is_empty() const;
   inline bool belongs(uint64_t pkt_hash) const;
   void create(const Packet &pkt, uint64_t pkt_hash);
   void update(const Packet &pkt, bool src);
};

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

class NHTFlowCache : TelemetryUtils, public StoragePlugin
{
public:
   NHTFlowCache();
   ~NHTFlowCache();
   void init(const char *params);
   void close();
   void set_queue(ipx_ring_t *queue);
   OptionsParser *get_parser() const { return new CacheOptParser(); }
   std::string get_name() const { return "cache"; }

   int put_pkt(Packet &pkt);
   void export_expired(time_t ts);

   /**
     * @brief Set and configure the telemetry directory where cache stats will be stored.
     */
   void set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir) override;

   #ifdef WITH_CTT

   int plugins_post_create(Flow &rec, Packet &pkt) {
      int ret = StoragePlugin::plugins_post_create(rec, pkt);
         rec.record_in_ctt = false;
         //if (only_metadata_required(rec)) {
         if (only_metadata_required(rec)) {
            m_ctt_controller.create_record(rec.flow_hash_ctt, rec.time_first);
            rec.record_in_ctt = true;
         }
      return ret;
   }

   // override post_update method
   int plugins_post_update(Flow &rec, Packet &pkt) {
      int ret = StoragePlugin::plugins_post_update(rec, pkt);
         //if (only_metadata_required(rec) && !rec.ctt_state) {
         if (!rec.record_in_ctt) { // only for debug!!!!! line above is correct for production
            m_ctt_controller.create_record(rec.flow_hash_ctt, rec.time_first);
            rec.record_in_ctt = true;
         }
      return ret;
   }

   // override pre_export method
   void plugins_pre_export(Flow &rec) {
      if (rec.record_in_ctt) {
         rec.is_delayed = true;
         rec.delay_time = time(nullptr) + 1;
         m_ctt_controller.export_record(rec.flow_hash_ctt);
         rec.record_in_ctt = false;
         return;
      }
      if (rec.is_delayed) {
         return;
      } else {
         StoragePlugin::plugins_pre_export(rec);
      }
   }

   #endif /* WITH_CTT */

private:
   uint32_t m_cache_size;
   uint32_t m_line_size;
   uint32_t m_line_mask;
   uint32_t m_line_new_idx;
   uint32_t m_qsize;
   uint32_t m_qidx;
   uint32_t m_timeout_idx;
   uint64_t m_flows_in_cache = 0;
   uint64_t m_total_exported = 0;
#ifdef FLOW_CACHE_STATS
   uint64_t m_empty;
   uint64_t m_not_empty;
   uint64_t m_hits;
   uint64_t m_expired;
   uint64_t m_flushed;
   uint64_t m_lookups;
   uint64_t m_lookups2;
#endif /* FLOW_CACHE_STATS */
   uint32_t m_active;
   uint32_t m_inactive;
   bool m_split_biflow;
   bool m_enable_fragmentation_cache;
   uint8_t m_keylen;
   char m_key[MAX_KEY_LENGTH];
   char m_key_inv[MAX_KEY_LENGTH];
   FlowRecord **m_flow_table;
   FlowRecord *m_flow_records;
#ifdef WITH_CTT
   CttController m_ctt_controller;
#endif /* WITH_CTT */
   FragmentationCache m_fragmentation_cache;
   FlowEndReasonStats m_flow_end_reason_stats = {};
   FlowRecordStats m_flow_record_stats = {};

   void try_to_fill_ports_to_fragmented_packet(Packet& packet);
   void flush(Packet &pkt, size_t flow_index, int ret, bool source_flow);
   bool create_hash_key(Packet &pkt);
   void export_flow(size_t index);
   static uint8_t get_export_reason(Flow &flow);
   void finish();

   void update_flow_end_reason_stats(uint8_t reason);
   void update_flow_record_stats(uint64_t packets_count);
   telemetry::Content get_cache_telemetry();
   void prefetch_export_expired() const;

#ifdef FLOW_CACHE_STATS
   void print_report();
#endif /* FLOW_CACHE_STATS */
};

}
#endif /* IPXP_STORAGE_CACHE_HPP */