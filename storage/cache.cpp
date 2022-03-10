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

#include <cstdlib>
#include <iostream>
#include <cstring>
#include <sys/time.h>

#include <ipfixprobe/ring.h>
#include "cache.hpp"
#include "xxhash.h"

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("cache", [](){return new NHTFlowCache();});
   register_plugin(&rec);
}

FlowRecord::FlowRecord()
{
   erase();
};

FlowRecord::~FlowRecord()
{
   erase();
};

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

void FlowRecord::create(const Packet &pkt, uint64_t hash)
{
   m_flow.src_packets = 1;

   m_hash = hash;

   m_flow.time_first = pkt.ts;
   m_flow.time_last = pkt.ts;

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
   } else if (pkt.ip_proto == IPPROTO_ICMP ||
      pkt.ip_proto == IPPROTO_ICMPV6) {
      m_flow.src_port = pkt.src_port;
      m_flow.dst_port = pkt.dst_port;
   }
}

void FlowRecord::update(const Packet &pkt, bool src)
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


NHTFlowCache::NHTFlowCache() :
   m_cache_size(0), m_line_size(0), m_line_mask(0), m_line_new_idx(0),
   m_qsize(0), m_qidx(0), m_timeout_idx(0), m_active(0), m_inactive(0),
   m_split_biflow(false), m_keylen(0), m_key(), m_key_inv(), m_flow_table(nullptr), m_flow_records(nullptr)
{
}

NHTFlowCache::~NHTFlowCache()
{
   close();
}

void NHTFlowCache::init(const char *params)
{
   CacheOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   m_cache_size = parser.m_cache_size;
   m_line_size = parser.m_line_size;
   m_active = parser.m_active;
   m_inactive = parser.m_inactive;
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
      m_flow_table = new FlowRecord*[m_cache_size + m_qsize];
      m_flow_records = new FlowRecord[m_cache_size + m_qsize];
      for (decltype(m_cache_size + m_qsize) i = 0; i < m_cache_size + m_qsize; i++) {
         m_flow_table[i] = m_flow_records + i;
      }
   } catch (std::bad_alloc &e) {
      throw PluginError("not enough memory for flow cache allocation");
   }

   m_split_biflow = parser.m_split_biflow;

#ifdef FLOW_CACHE_STATS
   m_empty = 0;
   m_not_empty = 0;
   m_hits = 0;
   m_expired = 0;
   m_flushed = 0;
   m_lookups = 0;
   m_lookups2 = 0;
#endif /* FLOW_CACHE_STATS */
}

void NHTFlowCache::close()
{
   if (m_flow_records != nullptr) {
      delete [] m_flow_records;
      m_flow_records = nullptr;
   }
   if (m_flow_table != nullptr) {
      delete [] m_flow_table;
      m_flow_table = nullptr;
   }
}

void NHTFlowCache::set_queue(ipx_ring_t *queue)
{
   m_export_queue = queue;
   m_qsize = ipx_ring_size(queue);
}

void NHTFlowCache::export_flow(size_t index)
{
   ipx_ring_push(m_export_queue, &m_flow_table[index]->m_flow);
   std::swap(m_flow_table[index], m_flow_table[m_cache_size + m_qidx]);
   m_flow_table[index]->erase();
   m_qidx = (m_qidx + 1) % m_qsize;
}

void NHTFlowCache::finish()
{
   for (decltype(m_cache_size) i = 0; i < m_cache_size; i++) {
      if (!m_flow_table[i]->is_empty()) {
         plugins_pre_export(m_flow_table[i]->m_flow);
         m_flow_table[i]->m_flow.end_reason = FLOW_END_FORCED;
         export_flow(i);
#ifdef FLOW_CACHE_STATS
         m_expired++;
#endif /* FLOW_CACHE_STATS */
      }
   }
}

void NHTFlowCache::flush(Packet &pkt, size_t flow_index, int ret, bool source_flow)
{
#ifdef FLOW_CACHE_STATS
   m_flushed++;
#endif /* FLOW_CACHE_STATS */

   if (ret == FLOW_FLUSH_WITH_REINSERT) {
      FlowRecord *flow = m_flow_table[flow_index];
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

int NHTFlowCache::put_pkt(Packet &pkt)
{
   int ret = plugins_pre_create(pkt);

   if (!create_hash_key(pkt)) { // saves key value and key length into attributes NHTFlowCache::key and NHTFlowCache::m_keylen
      return 0;
   }

   uint64_t hashval = XXH64(m_key, m_keylen, 0); /* Calculates hash value from key created before. */

   FlowRecord *flow; /* Pointer to flow we will be working with. */
   bool found = false;
   bool source_flow = true;
   uint32_t line_index = hashval & m_line_mask; /* Get index of flow line. */
   uint32_t flow_index = 0;
   uint32_t next_line = line_index + m_line_size;

   /* Find existing flow record in flow cache. */
   for (flow_index = line_index; flow_index < next_line; flow_index++) {
      if (m_flow_table[flow_index]->belongs(hashval)) {
         found = true;
         break;
      }
   }

   /* Find inversed flow. */
   if (!found && !m_split_biflow) {
      uint64_t hashval_inv = XXH64(m_key_inv, m_keylen, 0);
      uint64_t line_index_inv = hashval_inv & m_line_mask;
      uint64_t next_line_inv = line_index_inv + m_line_size;
      for (flow_index = line_index_inv; flow_index < next_line_inv; flow_index++) {
         if (m_flow_table[flow_index]->belongs(hashval_inv)) {
            found = true;
            source_flow = false;
            hashval = hashval_inv;
            line_index = line_index_inv;
            break;
         }
      }
   }

   if (found) {
      /* Existing flow record was found, put flow record at the first index of flow line. */
#ifdef FLOW_CACHE_STATS
      m_lookups += (flow_index - line_index + 1);
      m_lookups2 += (flow_index - line_index + 1) * (flow_index - line_index + 1);
#endif /* FLOW_CACHE_STATS */

      flow = m_flow_table[flow_index];
      for (decltype(flow_index) j = flow_index; j > line_index; j--) {
         m_flow_table[j] = m_flow_table[j - 1];
      }

      m_flow_table[line_index] = flow;
      flow_index = line_index;
#ifdef FLOW_CACHE_STATS
      m_hits++;
#endif /* FLOW_CACHE_STATS */
   } else {
      /* Existing flow record was not found. Find free place in flow line. */
      for (flow_index = line_index; flow_index < next_line; flow_index++) {
         if (m_flow_table[flow_index]->is_empty()) {
            found = true;
            break;
         }
      }
      if (!found) {
         /* If free place was not found (flow line is full), find
          * record which will be replaced by new record. */
         flow_index = next_line - 1;

         // Export flow
         plugins_pre_export(m_flow_table[flow_index]->m_flow);
         m_flow_table[flow_index]->m_flow.end_reason = FLOW_END_NO_RES;
         export_flow(flow_index);

#ifdef FLOW_CACHE_STATS
         m_expired++;
#endif /* FLOW_CACHE_STATS */
         uint32_t flow_new_index = line_index + m_line_new_idx;
         flow = m_flow_table[flow_index];
         for (decltype(flow_index) j = flow_index; j > flow_new_index; j--) {
            m_flow_table[j] = m_flow_table[j - 1];
         }
         flow_index = flow_new_index;
         m_flow_table[flow_new_index] = flow;
#ifdef FLOW_CACHE_STATS
         m_not_empty++;
      } else {
         m_empty++;
#endif /* FLOW_CACHE_STATS */
      }
   }

   pkt.source_pkt = source_flow;
   flow = m_flow_table[flow_index];

   uint8_t flw_flags = source_flow ? flow->m_flow.src_tcp_flags : flow->m_flow.dst_tcp_flags;
   if ((pkt.tcp_flags & 0x02) && (flw_flags & (0x01 | 0x04))) {
      // Flows with FIN or RST TCP flags are exported when new SYN packet arrives
      m_flow_table[flow_index]->m_flow.end_reason = FLOW_END_EOF;
      export_flow(flow_index);
      put_pkt(pkt);
      return 0;
   }

   if (flow->is_empty()) {
      flow->create(pkt, hashval);
      ret = plugins_post_create(flow->m_flow, pkt);

      if (ret & FLOW_FLUSH) {
         export_flow(flow_index);
#ifdef FLOW_CACHE_STATS
         m_flushed++;
#endif /* FLOW_CACHE_STATS */
      }
   } else {
      if (pkt.ts.tv_sec - flow->m_flow.time_last.tv_sec >= m_inactive) {
         m_flow_table[flow_index]->m_flow.end_reason = get_export_reason(flow->m_flow);
         plugins_pre_export(flow->m_flow);
         export_flow(flow_index);
   #ifdef FLOW_CACHE_STATS
         m_expired++;
   #endif /* FLOW_CACHE_STATS */
         return put_pkt(pkt);
      }
      ret = plugins_pre_update(flow->m_flow, pkt);
      if (ret & FLOW_FLUSH) {
         flush(pkt, flow_index, ret, source_flow);
         return 0;
      } else {
         flow->update(pkt, source_flow);
         ret = plugins_post_update(flow->m_flow, pkt);

         if (ret & FLOW_FLUSH) {
            flush(pkt, flow_index, ret, source_flow);
            return 0;
         }
      }

      /* Check if flow record is expired. */
      if (pkt.ts.tv_sec - flow->m_flow.time_first.tv_sec >= m_active) {
         m_flow_table[flow_index]->m_flow.end_reason = FLOW_END_ACTIVE;
         plugins_pre_export(flow->m_flow);
         export_flow(flow_index);
#ifdef FLOW_CACHE_STATS
         m_expired++;
#endif /* FLOW_CACHE_STATS */
      }
   }

   export_expired(pkt.ts.tv_sec);
   return 0;
}

uint8_t NHTFlowCache::get_export_reason(Flow &flow)
{
   if ((flow.src_tcp_flags | flow.dst_tcp_flags) & (0x01 | 0x04)) {
      // When FIN or RST is set, TCP connection ended naturally
      return FLOW_END_EOF;
   } else {
      return FLOW_END_INACTIVE;
   }
}

void NHTFlowCache::export_expired(time_t ts)
{
   for (decltype(m_timeout_idx) i = m_timeout_idx; i < m_timeout_idx + m_line_new_idx; i++) {
      if (!m_flow_table[i]->is_empty() && ts - m_flow_table[i]->m_flow.time_last.tv_sec >= m_inactive) {
         m_flow_table[i]->m_flow.end_reason = get_export_reason(m_flow_table[i]->m_flow);
         plugins_pre_export(m_flow_table[i]->m_flow);
         export_flow(i);
#ifdef FLOW_CACHE_STATS
         m_expired++;
#endif /* FLOW_CACHE_STATS */
      }
   }

   m_timeout_idx = (m_timeout_idx + m_line_new_idx) & (m_cache_size - 1);
}

bool NHTFlowCache::create_hash_key(Packet &pkt)
{
   if (pkt.ip_version == IP::v4) {
      struct flow_key_v4_t *key_v4 = reinterpret_cast<struct flow_key_v4_t *>(m_key);
      struct flow_key_v4_t *key_v4_inv = reinterpret_cast<struct flow_key_v4_t *>(m_key_inv);

      key_v4->proto = pkt.ip_proto;
      key_v4->ip_version = IP::v4;
      key_v4->src_port = pkt.src_port;
      key_v4->dst_port = pkt.dst_port;
      key_v4->src_ip = pkt.src_ip.v4;
      key_v4->dst_ip = pkt.dst_ip.v4;

      key_v4_inv->proto = pkt.ip_proto;
      key_v4_inv->ip_version = IP::v4;
      key_v4_inv->src_port = pkt.dst_port;
      key_v4_inv->dst_port = pkt.src_port;
      key_v4_inv->src_ip = pkt.dst_ip.v4;
      key_v4_inv->dst_ip = pkt.src_ip.v4;

      m_keylen = sizeof(flow_key_v4_t);
      return true;
   } else if (pkt.ip_version == IP::v6) {
      struct flow_key_v6_t *key_v6 = reinterpret_cast<struct flow_key_v6_t *>(m_key);
      struct flow_key_v6_t *key_v6_inv = reinterpret_cast<struct flow_key_v6_t *>(m_key_inv);

      key_v6->proto = pkt.ip_proto;
      key_v6->ip_version = IP::v6;
      key_v6->src_port = pkt.src_port;
      key_v6->dst_port = pkt.dst_port;
      memcpy(key_v6->src_ip, pkt.src_ip.v6, sizeof(pkt.src_ip.v6));
      memcpy(key_v6->dst_ip, pkt.dst_ip.v6, sizeof(pkt.dst_ip.v6));

      key_v6_inv->proto = pkt.ip_proto;
      key_v6_inv->ip_version = IP::v6;
      key_v6_inv->src_port = pkt.dst_port;
      key_v6_inv->dst_port = pkt.src_port;
      memcpy(key_v6_inv->src_ip, pkt.dst_ip.v6, sizeof(pkt.dst_ip.v6));
      memcpy(key_v6_inv->dst_ip, pkt.src_ip.v6, sizeof(pkt.src_ip.v6));

      m_keylen = sizeof(flow_key_v6_t);
      return true;
   }

   return false;
}

#ifdef FLOW_CACHE_STATS
void NHTFlowCache::print_report()
{
   float tmp = float(m_lookups) / m_hits;

   cout << "Hits: " << m_hits << endl;
   cout << "Empty: " << m_empty << endl;
   cout << "Not empty: " << m_not_empty << endl;
   cout << "Expired: " << m_expired << endl;
   cout << "Flushed: " << m_flushed << endl;
   cout << "Average Lookup:  " << tmp << endl;
   cout << "Variance Lookup: " << float(m_lookups2) / m_hits - tmp * tmp << endl;
}
#endif /* FLOW_CACHE_STATS */

}
