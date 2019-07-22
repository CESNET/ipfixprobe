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

#ifndef _TYPES_P4_
#define _TYPES_P4_

#include "headers.p4"

header ipaddrv4_h {
   bit<32> addr;
}
header ipaddrv6_h {
   bit<128> addr;
}
header_union ipaddr_u {
   ipaddrv4_h v4;
   ipaddrv6_h v6;
}

// Struct with headers that are going to be parsed by parser
struct headers_s {
   ethernet_h eth;
   ipv4_h ipv4;
   ipv6_h ipv6;
   tcp_h tcp;
   udp_h udp;
   icmp_h icmp;
   icmpv6_h icmp6;
   payload_h payload;
}

// Struct representing flow cache record
struct flowrec_s {
   bit<64> bytes;
   bit<32> packets;
   bit<8> tcpflags;

   bit<8> ip_version;
   bit<8> tos;
   bit<8> ttl;

   bit<8> protocol;
   bit<16> src_port;
   bit<16> dst_port;
   ipaddr_u src_addr;
   ipaddr_u dst_addr;

   bit<48> src_hwaddr;
   bit<48> dst_hwaddr;
}

#endif // _TYPES_P4_