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
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */
#ifndef IPXP_STORAGE_CACHE_HPP
#define IPXP_STORAGE_CACHE_HPP

#include <string>

#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

struct __attribute__((packed)) flow_key_v4_t {
   uint16_t src_port;
   uint16_t dst_port;
   uint8_t proto;
   uint8_t ip_version;
   uint32_t src_ip;
   uint32_t dst_ip;
};

struct __attribute__((packed)) flow_key_v6_t {
   uint16_t src_port;
   uint16_t dst_port;
   uint8_t proto;
   uint8_t ip_version;
   uint8_t src_ip[16];
   uint8_t dst_ip[16];
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

   CacheOptParser() : OptionsParser("cache", "Storage plugin implemented as a hash table"),
      m_cache_size(1 << DEFAULT_FLOW_CACHE_SIZE), m_line_size(1 << DEFAULT_FLOW_LINE_SIZE),
      m_active(DEFAULT_ACTIVE_TIMEOUT), m_inactive(DEFAULT_INACTIVE_TIMEOUT), m_split_biflow(false)
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
   }
};

class FlowRecord
{
   uint64_t m_hash;

public:
   Flow m_flow;

   FlowRecord();
   ~FlowRecord();

   void erase();
   void reuse();

   inline bool is_empty() const;
   inline bool belongs(uint64_t pkt_hash) const;
   void create(const Packet &pkt, uint64_t pkt_hash);
   void update(const Packet &pkt, bool src);
};

class NHTFlowCache : public StoragePlugin
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

private:
   uint32_t m_cache_size;
   uint32_t m_line_size;
   uint32_t m_line_mask;
   uint32_t m_line_new_idx;
   uint32_t m_qsize;
   uint32_t m_qidx;
   uint32_t m_timeout_idx;
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
   uint8_t m_keylen;
   char m_key[MAX_KEY_LENGTH];
   char m_key_inv[MAX_KEY_LENGTH];
   FlowRecord **m_flow_table;
   FlowRecord *m_flow_records;

   void flush(Packet &pkt, size_t flow_index, int ret, bool source_flow);
   bool create_hash_key(Packet &pkt);
   void export_flow(size_t index);
   static uint8_t get_export_reason(Flow &flow);
   void finish();

#ifdef FLOW_CACHE_STATS
   void print_report();
#endif /* FLOW_CACHE_STATS */
};

}
#endif /* IPXP_STORAGE_CACHE_HPP */
