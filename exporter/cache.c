/**
 * \file cache.c
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>

#include "xxhash.h"
#include "types.h"
#include "parser.h"
#include "plugin.h"
#include "cache.h"

// TODO: memset 0 record when rec is exported or rejected, not everytime packet arrives

void print_flow(struct flowrec_s *flow)
{
   char src_ip[INET6_ADDRSTRLEN];
   char dst_ip[INET6_ADDRSTRLEN];
   char timestamp_first[32];
   char timestamp_last[32];
   time_t time_first = flow->first.tv_sec;
   time_t time_last = flow->last.tv_sec;

   strftime(timestamp_first, sizeof(timestamp_first), "%FT%T", localtime(&time_first));
   strftime(timestamp_last, sizeof(timestamp_last), "%FT%T", localtime(&time_last));

   if (flow->ip_version == 4) {
      flow->src_addr.v4.addr = ntohl(flow->src_addr.v4.addr);
      flow->dst_addr.v4.addr = ntohl(flow->dst_addr.v4.addr);
      inet_ntop(AF_INET, (const void *) &flow->src_addr.v4.addr, src_ip, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET, (const void *) &flow->dst_addr.v4.addr, dst_ip, INET6_ADDRSTRLEN);
      fprintf(stderr, "%u@%s:%u->%s:%u#", flow->protocol, src_ip, flow->src_port, dst_ip, flow->dst_port);
   } else {
      inet_ntop(AF_INET6, (const void *) &flow->src_addr.v6.addr, src_ip, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, (const void *) &flow->dst_addr.v6.addr, dst_ip, INET6_ADDRSTRLEN);
      fprintf(stderr, "%u@[%s]:%u->[%s]:%u#", flow->protocol, src_ip, flow->src_port, dst_ip, flow->dst_port);
   }
   fprintf(stderr, " %s.%06lu<->%s.%06lu", timestamp_first, flow->first.tv_usec, timestamp_last, flow->last.tv_usec);
   fprintf(stderr, " packets=%u bytes=%lu", flow->packets, flow->bytes);
   fprintf(stderr, " tos=%u ttl=%u tcpflags=%u", flow->tos, flow->ttl, flow->tcpflags);
   fprintf(stderr, " id=%lu parent=%lu", flow->id, flow->parent);
   fprintf(stderr, "\n");
}

int cache_create_flow(struct packet_hdr_s *packet, struct flowrec_s *flow, uint8_t *key, uint32_t *key_len, struct packet_hdr_s **next_flow, ssize_t *payload_offset)
{ 
   uint8_t tmp_19;
   uint8_t tmp_20;
   uint8_t tmp_21;
   uint8_t tmp_22;
   uint8_t tmp_23;
   uint8_t tmp_24;
   uint8_t tmp_25;

   (void) tmp_19;
   (void) tmp_20;
   (void) tmp_21;
   (void) tmp_22;
   (void) tmp_23;
   (void) tmp_24;
   (void) tmp_25;

   int success = 0;
   uint8_t headers[8] = {0};
   struct packet_hdr_s *hdr = packet;
   *key_len = 0;

   memset(flow, 0, sizeof(*flow));
   while (hdr != NULL) {
      if (hdr->type == payload_h) {
         *payload_offset = hdr->header_offset;
         hdr = hdr->next;
         break;
      }
      if (headers[hdr->type] || ((hdr->type == ipv4_h && headers[ipv6_h]) || (hdr->type == ipv6_h && headers[ipv4_h]))) {
         *next_flow = hdr;
         return success;
      }
      headers[hdr->type] = 1;
      tmp_25 = (hdr->type == ethernet_h);
      if (tmp_25) {
         flow[0].src_hwaddr = ((struct ethernet_h *) hdr->data)[0].src_addr;
         flow[0].dst_hwaddr = ((struct ethernet_h *) hdr->data)[0].dst_addr;
      } else {
         tmp_24 = (hdr->type == ipv4_h);
         if (tmp_24) {
            success = 1;
            flow[0].ip_version = 4;
            *(uint8_t *)(key + *key_len) = 4;
            *key_len += 1;
            *(uint32_t *)(key + *key_len) = ((struct ipv4_h *) hdr->data)[0].src_addr;
            *key_len += 4;
            *(uint32_t *)(key + *key_len) = ((struct ipv4_h *) hdr->data)[0].dst_addr;
            *key_len += 4;
            *(uint8_t *)(key + *key_len) = ((struct ipv4_h *) hdr->data)[0].protocol;
            *key_len += 1;
            flow[0].src_addr.v4.addr = ((struct ipv4_h *) hdr->data)[0].src_addr;
            flow[0].dst_addr.v4.addr = ((struct ipv4_h *) hdr->data)[0].dst_addr;
            flow[0].protocol = ((struct ipv4_h *) hdr->data)[0].protocol;
            flow[0].tos = ((struct ipv4_h *) hdr->data)[0].diffserv;
            flow[0].ttl = ((struct ipv4_h *) hdr->data)[0].ttl;
         } else {
            tmp_23 = (hdr->type == ipv6_h);
            if (tmp_23) {
               success = 1;
               flow[0].ip_version = 6;
               *(uint8_t *)(key + *key_len) = 6;
               *key_len += 1;
               memcpy((key + *key_len), ((struct ipv6_h *) hdr->data)[0].src_addr, 16);
               *key_len += 16;
               memcpy((key + *key_len), ((struct ipv6_h *) hdr->data)[0].dst_addr, 16);
               *key_len += 16;
               *(uint8_t *)(key + *key_len) = ((struct ipv6_h *) hdr->data)[0].next_hdr;
               *key_len += 1;
               memcpy(flow[0].src_addr.v6.addr, ((struct ipv6_h *) hdr->data)[0].src_addr, 16);
               memcpy(flow[0].dst_addr.v6.addr, ((struct ipv6_h *) hdr->data)[0].dst_addr, 16);
               flow[0].tos = ((((struct ipv6_h *) hdr->data)[0].traffic_class) & (252)) >> (2);
               flow[0].ttl = ((struct ipv6_h *) hdr->data)[0].hop_limit;
               flow[0].protocol = ((struct ipv6_h *) hdr->data)[0].next_hdr;
            } else {
               tmp_22 = (hdr->type == udp_h);
               if (tmp_22) {
                  *(uint16_t *)(key + *key_len) = ((struct udp_h *) hdr->data)[0].src_port;
                  *key_len += 2;
                  *(uint16_t *)(key + *key_len) = ((struct udp_h *) hdr->data)[0].dst_port;
                  *key_len += 2;
                  flow[0].src_port = ((struct udp_h *) hdr->data)[0].src_port;
                  flow[0].dst_port = ((struct udp_h *) hdr->data)[0].dst_port;
               } else {
                  tmp_21 = (hdr->type == tcp_h);
                  if (tmp_21) {
                     *(uint16_t *)(key + *key_len) = ((struct tcp_h *) hdr->data)[0].src_port;
                     *key_len += 2;
                     *(uint16_t *)(key + *key_len) = ((struct tcp_h *) hdr->data)[0].dst_port;
                     *key_len += 2;
                     flow[0].src_port = ((struct tcp_h *) hdr->data)[0].src_port;
                     flow[0].dst_port = ((struct tcp_h *) hdr->data)[0].dst_port;
                  } else {
                     tmp_20 = (hdr->type == icmp_h);
                     if (tmp_20) {
                        flow[0].src_port = 0;
                        flow[0].dst_port = (((uint16_t)(((struct icmp_h *) hdr->data)[0].type_)) << (8)) + ((uint16_t)(((struct icmp_h *) hdr->data)[0].code));
                        *(uint16_t *)(key + *key_len) = 0;
                        *key_len += 2;
                        *(uint16_t *)(key + *key_len) = (((uint16_t)(((struct icmp_h *) hdr->data)[0].type_)) << (8)) + ((uint16_t)(((struct icmp_h *) hdr->data)[0].code));
                        *key_len += 2;
                     } else {
                        tmp_19 = (hdr->type == icmpv6_h);
                        if (tmp_19) {
                           flow[0].src_port = 0;
                           flow[0].dst_port = (((uint16_t)(((struct icmpv6_h *) hdr->data)[0].type_)) << (8)) + ((uint16_t)(((struct icmpv6_h *) hdr->data)[0].code));
                           *(uint16_t *)(key + *key_len) = 0;
                           *key_len += 2;
                           *(uint16_t *)(key + *key_len) = (((uint16_t)(((struct icmpv6_h *) hdr->data)[0].type_)) << (8)) + ((uint16_t)(((struct icmpv6_h *) hdr->data)[0].code));
                           *key_len += 2;
                        }
                     }
                  }
               }
            }
         }
      }
      hdr = hdr->next;
   }
   *next_flow = hdr;

   return success;
}

void cache_update_flow(struct packet_hdr_s *packet, struct flowrec_s *flow)
{ 
   uint8_t tmp_26;
   uint8_t tmp_27;
   uint8_t tmp_28;

   (void) tmp_26;
   (void) tmp_27;
   (void) tmp_28;

   uint8_t headers[8] = {0};
   struct packet_hdr_s *hdr = packet;
   while (hdr != NULL) { 
      if (headers[hdr->type] || ((hdr->type == ipv4_h && headers[ipv6_h]) || (hdr->type == ipv6_h && headers[ipv4_h]))) {
         return;
      }
      headers[hdr->type] = 1;
      tmp_28 = (hdr->type == ipv4_h);
      if (tmp_28) {
         flow[0].bytes = (flow[0].bytes) + ((uint64_t)(((struct ipv4_h *) hdr->data)[0].total_len));
         flow[0].packets = (flow[0].packets) + (1);
      } else {
         tmp_27 = (hdr->type == ipv6_h);
         if (tmp_27) {
            flow[0].bytes = ((flow[0].bytes) + ((uint64_t)(((struct ipv6_h *) hdr->data)[0].payload_len))) + (40);
            flow[0].packets = (flow[0].packets) + (1);
         } else {
            tmp_26 = (hdr->type == tcp_h);
            if (tmp_26) {
               flow[0].tcpflags = (flow[0].tcpflags) | (((struct tcp_h *) hdr->data)[0].flags);
            }
         }
      }
      hdr = hdr->next;
   }
}

void cache_export_flow(struct flowcache_s *cache, struct cacherec_s *rec)
{
   ipfix_export_flow(cache->ipfix, rec->flow);
   //print_flow(rec->flow);

   struct flowext_s *ext = rec->flow->ext;
   while (ext != NULL) {
      struct flowext_s *tmp = ext->next;
      free(ext->data);
      free(ext);
      ext = tmp;
   }

   cache->flows_free_cnt++;
   cache->flows_free[cache->flows_free_cnt - 1] = rec->flow;
   cache->flows_current--;

   rec->hash = 0;
   rec->flow = NULL;
}

uint32_t cache_find_flow(struct flowcache_s *cache, uint64_t hash)
{
   struct cacherec_s *rec;
   uint32_t line_index = hash & cache->mask;
   uint32_t flow_index;
   uint32_t line_end = line_index + cache->line_size;

   // find if flow exists in cache
   for (flow_index = line_index; flow_index < line_end; flow_index++) {
      if (cache->cache[flow_index]->hash == hash) {
         break;
      }
   }

   if (flow_index < line_end) {
      // flow was found
      rec = cache->cache[flow_index];
      for (uint32_t i = flow_index; i > line_index; i--) {
         cache->cache[i] = cache->cache[i - 1];
      }

      cache->cache[line_index] = rec;
      flow_index = line_index;
   } else {
      // flow was not found
      for (flow_index = line_index; flow_index < line_end; flow_index++) {
         if (cache->cache[flow_index]->hash == 0) {
            break;
         }
      }
      if (flow_index >= line_end) {
         // take flow from the end and export it
         uint32_t flow_index_new = line_index + cache->new_index_offset;
         flow_index = line_end - 1;
         rec = cache->cache[flow_index];

         cache_export_flow(cache, rec);

         for (uint32_t i = flow_index; i > flow_index_new; i--) {
            cache->cache[i] = cache->cache[i - 1];
         }

         flow_index = flow_index_new;
         cache->cache[flow_index] = rec;
      }
   }

   return flow_index;
}

void cache_add_packet(struct flowcache_s *cache, struct packet_hdr_s *packet, struct timeval time, uint64_t parent,
   const uint8_t *packet_bytes, uint32_t packet_len)
{
   const uint8_t *payload = NULL;
   size_t payload_len = 0;
   ssize_t payload_offset = 0;

   uint8_t key[60];
   uint32_t key_len = 0;
   struct packet_hdr_s *next_flow = NULL;
   struct flowrec_s *flow = cache->flows_free[cache->flows_free_cnt - 1];
   cache->flows_free_cnt--;

   // process input packet
   int status = cache_create_flow(packet, flow, key, &key_len, &next_flow, &payload_offset);
   if (!status) {
      cache->flows_free_cnt++;
      if (next_flow != NULL) {
         cache_add_packet(cache, next_flow, time, 0, packet_bytes, packet_len);
      }
      return;
   }
   cache->packets_total++;

   if (payload_offset > 0) {
      payload_len = packet_len - payload_offset;
      payload = packet_bytes + payload_offset;
   }

   uint64_t hash = XXH64(key, key_len, 0);

   uint32_t flow_index = cache_find_flow(cache, hash);
   struct cacherec_s *rec = cache->cache[flow_index];

   if (rec->flow == NULL) {
      rec->hash = hash;
      rec->flow = flow;
      rec->flow->first = time;
      rec->flow->id = hash;
      rec->flow->parent = parent;
      cache->flows_total++;
      cache->flows_current++;

      // update flow
      rec->flow->last = time;
      cache_update_flow(packet, rec->flow);

      if (cache_post_create(cache, flow, payload, payload_len) & FLOW_FLUSH) {
         cache_export_flow(cache, rec);
         return;
      }
   } else {
      cache->flows_free_cnt++;
      cache->flows_free[cache->flows_free_cnt - 1] = flow; // TODO: delete?

      if (cache_pre_update(cache, rec->flow, payload, payload_len) & FLOW_FLUSH) {
         cache_export_flow(cache, rec);
         cache_add_packet(cache, packet, time, parent, packet_bytes, packet_len);
         return;
      }

      // update flow
      rec->flow->last = time;
      cache_update_flow(packet, rec->flow);
   }

   // check active timeout
   if (time.tv_sec - rec->flow->first.tv_sec >= cache->active) {
      cache_export_flow(cache, rec);
   }

   if (time.tv_sec - cache->last_time.tv_sec > 5) {
      cache_export_expired(cache, time.tv_sec);
      cache->last_time = time;
   }

   if (next_flow != NULL) {
      cache_add_packet(cache, next_flow, time, hash, packet_bytes, packet_len);
   }
}

void flow_add_extension(struct flowrec_s *flow, void *ext, uint32_t id)
{
   struct flowext_s *tmp = (struct flowext_s *) malloc(sizeof(struct flowext_s));
   tmp->id = id;
   tmp->data = ext;
   tmp->next = flow->ext;
   flow->ext = tmp;
}
int flow_get_extension(struct flowrec_s *flow, void **ext, uint32_t id)
{
   struct flowext_s *tmp = flow->ext;
   while (tmp != NULL) {
      if (tmp->id == id) {
         *ext = tmp->data;
         return 1;
      }
      tmp = tmp->next;
   }
   return 0;
}

int cache_post_create(struct flowcache_s *cache, struct flowrec_s *flow, const uint8_t *payload, uint32_t payload_len)
{
   int ret = 0;
   int i;
   for (i = 0; i < cache->plugin_cnt; i++) {
      ret |= cache->plugins[i].create(flow, payload, payload_len);
   }
   return ret;
}

int cache_pre_update(struct flowcache_s *cache, struct flowrec_s *flow, const uint8_t *payload, uint32_t payload_len)
{
   int ret = 0;
   int i;
   for (i = 0; i < cache->plugin_cnt; i++) {
      ret |= cache->plugins[i].update(flow, payload, payload_len);
   }
   return ret;
}

int cache_init(struct flowcache_s *cache, uint32_t cache_size, uint32_t line_size, uint32_t active, uint32_t inactive, struct ipfix_s *ipfix, const char *plugins)
{
   cache->ipfix = ipfix;

   cache->cache_size = cache_size; // must be power of 2
   cache->cache = (struct cacherec_s **) malloc(cache->cache_size * sizeof(struct cacherec_s *));
   cache->flows_free = (struct flowrec_s **) malloc((cache->cache_size + 1) * sizeof(struct flowrec_s *));

   cache->flows_free_cnt = cache->cache_size + 1;
   cache->last_time = (struct timeval) {0, 0};

   cache->plugin_cnt = 0;
   cache->plugins = NULL;

   cache->line_size = line_size;
   cache->new_index_offset = cache->line_size / 2;
   cache->mask = (cache->cache_size - 1) & ~(cache->line_size - 1);
   cache->active = active;
   cache->inactive = inactive;

   cache->packets_total = 0;
   cache->flows_current = 0;
   cache->flows_total = 0;

   cache->records = (struct cacherec_s *) malloc(cache->cache_size * sizeof(struct cacherec_s));
   cache->flows = (struct flowrec_s *) malloc((cache->cache_size + 1) * sizeof(struct flowrec_s));

   if (cache->cache == NULL || cache->flows_free == NULL || cache->records == NULL || cache->flows == NULL) {
      free(cache->cache);
      free(cache->flows_free);
      free(cache->records);
      free(cache->flows);
      return 0;
   }

   for (int i = 0; i < cache->cache_size; i++) {
      cache->flows_free[i] = &cache->flows[i];
      cache->cache[i] = &cache->records[i];

      cache->cache[i]->hash = 0;
      cache->cache[i]->flow = NULL;
   }

   // Init the (cache->cache_size + 1)th record
   cache->flows_free[cache->cache_size] = &cache->flows[cache->cache_size];

   memset(cache->records, 0, sizeof(*cache->records) * cache->cache_size);

   if (plugins != NULL && !add_plugins(cache, plugins)) {
      free(cache->cache);
      free(cache->flows_free);
      free(cache->records);
      free(cache->flows);
      return 0;
   }

   return 1;
}

void cache_export_expired(struct flowcache_s *cache, time_t time)
{
   for (uint32_t i = 0; i < cache->cache_size; i++) {
      struct cacherec_s *rec = cache->cache[i];
      if (rec->hash != 0 && time - rec->flow->last.tv_sec >= cache->inactive) {
         cache_export_flow(cache, rec);
      }
   }
   ipfix_flush(cache->ipfix);
}

void cache_export_all(struct flowcache_s *cache)
{
   for (uint32_t i = 0; i < cache->cache_size; i++) {
      struct cacherec_s *rec = cache->cache[i];
      if (rec->hash != 0) {
         cache_export_flow(cache, rec);
      }
   }
}

void cache_clear(struct flowcache_s *cache)
{
   free(cache->cache);
   free(cache->flows_free);
   free(cache->records);
   free(cache->flows);
   free(cache->plugins);
   finish_plugins();
}
