/**
 * \file cache.h
 * \date 2019
 * \author Jiri Havranek <havranek@cesnet.cz>
 */
/*
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
*/

#ifndef P4E_GENERATED_CACHE
#define P4E_GENERATED_CACHE

#include "types.h"
#include "parser.h"
#include "ipfix.h"

#define FLOW_FLUSH 1
#define FLOW_EXPORT 2

struct cacherec_s {
   uint64_t hash;
   struct flowrec_s *flow;
};

struct plugin_s {
   uint32_t id;
   const char *name;
   int (*create)(struct flowrec_s *, const uint8_t *, int);
   int (*update)(struct flowrec_s *, const uint8_t *, int);
};

struct flowext_s {
   uint32_t id;
   void *data;
   struct flowext_s *next;
};

struct flowcache_s {
   struct ipfix_s *ipfix;
   struct cacherec_s **cache;
   struct flowrec_s **flows_free;
   uint32_t flows_free_cnt;
   struct timeval last_time;

   uint32_t plugin_cnt;
   struct plugin_s *plugins;

   uint32_t cache_size;
   uint32_t line_size;
   uint32_t new_index_offset;
   uint32_t mask;

   uint32_t active;
   uint32_t inactive;

   uint64_t packets_total;
   uint64_t flows_current;
   uint64_t flows_total;

   struct cacherec_s *records;
   struct flowrec_s *flows;
};

int cache_create_flow(struct packet_hdr_s *packet, struct flowrec_s *flow, uint8_t *key, uint32_t *key_len, struct packet_hdr_s **next_flow, ssize_t *payload_offset);
void cache_update_flow(struct packet_hdr_s *packet, struct flowrec_s *flow);
uint32_t cache_find_flow(struct flowcache_s *cache, uint64_t hash);
void cache_add_packet(struct flowcache_s *cache, struct packet_hdr_s *packet, struct timeval time, uint64_t parent, const uint8_t *packet_bytes, uint32_t packet_len);
void flow_add_extension(struct flowrec_s *flow, void *ext, uint32_t id);
int flow_get_extension(struct flowrec_s *flow, void **ext, uint32_t id);
int cache_post_create(struct flowcache_s *cache, struct flowrec_s *flow, const uint8_t *payload, uint32_t payload_len);
int cache_pre_update(struct flowcache_s *cache, struct flowrec_s *flow, const uint8_t *payload, uint32_t payload_len);
int cache_init(struct flowcache_s *cache, uint32_t cache_size, uint32_t line_size, uint32_t active, uint32_t inactive, struct ipfix_s *ipfix, const char *plugins);
void cache_export_expired(struct flowcache_s *cache, time_t time);
void cache_export_all(struct flowcache_s *cache);
void cache_clear(struct flowcache_s *cache);

#endif
