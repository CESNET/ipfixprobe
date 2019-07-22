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

#ifndef _CACHE_P4_
#define _CACHE_P4_

#include "types.p4"

extern flowcache {
   // Add field or header into flow key
   void add_to_key<T>(in T hdr);

   // Check if given header is present
   bool is_present<T>(in T hdr);

   // Check if next header is present
   bool is_next<T>(in T hdr);

   // Register conflicting types, when one of the headers is processed and other one was already processed before the flow is split
   // Headers of same types are automatically split into separated flows
   void register_conflicting_headers<T1, T2>(in T1 hdr1, in T2 hdr2);
}

control flow_create(in headers_s headers, flowcache c, out flowrec_s flow, out bool success)
{
   apply {
      c.register_conflicting_headers(headers.ipv4, headers.ipv6);

      if (c.is_present(headers.eth)) {
         flow.src_hwaddr = headers.eth.src_addr;
         flow.dst_hwaddr = headers.eth.dst_addr;
      } else if (c.is_present(headers.ipv4)) {
         success = true;
         flow.ip_version = 4;
         c.add_to_key(flow.ip_version);
         c.add_to_key(headers.ipv4.src_addr);
         c.add_to_key(headers.ipv4.dst_addr);
         c.add_to_key(headers.ipv4.protocol);

         flow.src_addr.v4.addr = headers.ipv4.src_addr;
         flow.dst_addr.v4.addr = headers.ipv4.dst_addr;
         flow.protocol = headers.ipv4.protocol;
         flow.tos = headers.ipv4.diffserv;
         flow.ttl = headers.ipv4.ttl;
      } else if (c.is_present(headers.ipv6)) {
         success = true;
         flow.ip_version = 6;
         c.add_to_key(flow.ip_version);
         c.add_to_key(headers.ipv6.src_addr);
         c.add_to_key(headers.ipv6.dst_addr);
         c.add_to_key(headers.ipv6.next_hdr);

         flow.src_addr.v6.addr = headers.ipv6.src_addr;
         flow.dst_addr.v6.addr = headers.ipv6.dst_addr;
         flow.tos = (headers.ipv6.traffic_class & 0xFC) >> 2;
         flow.ttl = headers.ipv6.hop_limit;
         flow.protocol = headers.ipv6.next_hdr;
      } else if (c.is_present(headers.udp)) {
         c.add_to_key(headers.udp.src_port);
         c.add_to_key(headers.udp.dst_port);

         flow.src_port = headers.udp.src_port;
         flow.dst_port = headers.udp.dst_port;
      } else if (c.is_present(headers.tcp)) {
         c.add_to_key(headers.tcp.src_port);
         c.add_to_key(headers.tcp.dst_port);

         flow.src_port = headers.tcp.src_port;
         flow.dst_port = headers.tcp.dst_port;
      } else if (c.is_present(headers.icmp)) {
         flow.src_port = 0;
         flow.dst_port = (bit<16>) headers.icmp.type_ * 256 + (bit<16>) headers.icmp.code;

         c.add_to_key(flow.src_port);
         c.add_to_key(flow.dst_port);
      } else if (c.is_present(headers.icmp6)) {
         flow.src_port = 0;
         flow.dst_port = (bit<16>) headers.icmp6.type_ * 256 + (bit<16>) headers.icmp6.code;

         c.add_to_key(flow.src_port);
         c.add_to_key(flow.dst_port);
      }
   }
}

control flow_update(in headers_s headers, flowcache c, out flowrec_s flow)
{
   apply {
      c.register_conflicting_headers(headers.ipv4, headers.ipv6);

      if (c.is_present(headers.ipv4)) {
         flow.bytes = flow.bytes + (bit<64>) headers.ipv4.total_len;
         flow.packets = flow.packets + 1;
      } else if (c.is_present(headers.ipv6)) {
         flow.bytes = flow.bytes + (bit<64>) headers.ipv6.payload_len + 40;
         flow.packets = flow.packets + 1;
      } else if (c.is_present(headers.tcp)) {
         flow.tcpflags = flow.tcpflags | headers.tcp.flags;
      }
   }
}

#endif // _CACHE_P4_
