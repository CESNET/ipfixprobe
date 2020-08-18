/**
 * \file nhtflowcache.h
 * \brief "NewHashTable" flow cache
 * \author Martin Zadnik <zadnik@cesnet.cz>
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
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
#ifndef NHTFLOWCACHE_H
#define NHTFLOWCACHE_H

#include <string>

#include "flow_meter.h"
#include "flowcache.h"
#include "flowifc.h"
#include "flowexporter.h"

using namespace std;

#define MAX_KEY_LENGTH 38
#define INACTIVE_CHECK_PERIOD_1 5 // Inactive timeout of flows will be checked every X seconds when packets are continuously arriving
#define INACTIVE_CHECK_PERIOD_2 1 // Inactive timeout of flows will be checked every X seconds when packet read timeout occured or read is nonblocking

class FlowRecord
{
   uint64_t hash;
public:
   Flow flow;

   void erase()
   {
      flow.removeExtensions();
      hash = 0;

      memset(&flow.time_first, 0, sizeof(flow.time_first));
      memset(&flow.time_last, 0, sizeof(flow.time_last));
      flow.ip_version = 0;
      flow.ip_proto = 0;
      memset(&flow.src_ip, 0, sizeof(flow.src_ip));
      memset(&flow.dst_ip, 0, sizeof(flow.dst_ip));
      flow.src_port = 0;
      flow.dst_port = 0;
      flow.src_pkt_total_cnt = 0;
      flow.dst_pkt_total_cnt = 0;
      flow.src_octet_total_length = 0;
      flow.dst_octet_total_length = 0;
      flow.src_tcp_control_bits = 0;
      flow.dst_tcp_control_bits = 0;
   }
   void soft_clean()
   {
      flow.removeExtensions();
      flow.time_first = flow.time_last;
      flow.src_pkt_total_cnt = 0;
      flow.dst_pkt_total_cnt = 0;
      flow.src_octet_total_length = 0;
      flow.dst_octet_total_length = 0;
      flow.src_tcp_control_bits = 0;
      flow.dst_tcp_control_bits = 0;
   }

   FlowRecord()
   {
      erase();
   };
   ~FlowRecord()
   {
   };

   inline bool is_empty() const;
   inline bool belongs(uint64_t pkt_hash) const;
   void create(const Packet &pkt, uint64_t pkt_hash);
   void update(const Packet &pkt, bool src);
};

class NHTFlowCache : public FlowCache
{
   bool print_stats;
   uint8_t key_len;
   uint32_t size;
   uint32_t line_size;
   uint32_t line_size_mask;
   uint32_t line_new_index;
#ifdef FLOW_CACHE_STATS
   uint64_t empty;
   uint64_t not_empty;
   uint64_t hits;
   uint64_t expired;
   uint64_t flushed;
   uint64_t lookups;
   uint64_t lookups2;
#endif /* FLOW_CACHE_STATS */
   struct timeval current_ts;
   time_t last_ts;
   struct timeval active;
   struct timeval inactive;
   char key[MAX_KEY_LENGTH];
   char key_inv[MAX_KEY_LENGTH];
   FlowRecord **flow_array;
   FlowRecord *flow_records;

public:
   NHTFlowCache(const options_t &options)
   {
      size = options.flow_cache_size;
      line_size = options.flow_line_size;
      /* Mask for getting flow cache line index. */
      line_size_mask = (size - 1) & ~(line_size - 1);
      line_new_index = line_size / 2;
#ifdef FLOW_CACHE_STATS
      empty = 0;
      not_empty = 0;
      hits = 0;
      expired = 0;
      flushed = 0;
      lookups = 0;
      lookups2 = 0;
#endif /* FLOW_CACHE_STATS */
      last_ts = 0;
      print_stats = options.print_stats;
      active = options.active_timeout;
      inactive = options.inactive_timeout;

      flow_array = new FlowRecord*[size];
      flow_records = new FlowRecord[size];
      for (unsigned int i = 0; i < size; i++) {
         flow_array[i] = flow_records + i;
      }
   };
   ~NHTFlowCache()
   {
      delete [] flow_records;
      delete [] flow_array;
   };

// Put packet into the cache (i.e. update corresponding flow record or create a new one)
   virtual int put_pkt(Packet &pkt);
   virtual void init();
   virtual void finish();

   void export_expired(time_t ts);
   void flush(Packet &pkt, FlowRecord *flow, int ret, bool source_flow);

protected:
   bool create_hash_key(Packet &pkt);
   void print_report();
};

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

#endif
