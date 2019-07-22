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

#ifndef _PARSER_P4_
#define _PARSER_P4_

#include <core.p4>

#include "headers.p4"

#define SWITCH_IPV6 \
   IPPROTO_TCP: parse_tcp; \
   IPPROTO_UDP: parse_udp; \
   IPPROTO_ICMPV6: parse_icmp6; \
   IPPROTO_IPIP: parse_ipv4; \
   IPPROTO_IPV6: parse_ipv6; \
   IPPROTO_GRE: parse_gre; \
   IPPROTO_ETHERIP: parse_etherip; \
   IPPROTO_MPLS: parse_mpls; \
   IPPROTO_IPV6_HOP_OPT: parse_ipv6_hop_opt; \
   IPPROTO_IPV6_DST_OPT: parse_ipv6_dst_opt; \
   IPPROTO_IPV6_ROUTING: parse_ipv6_routing; \
   IPPROTO_IPV6_FRAGMENT: parse_ipv6_fragment; \
   IPPROTO_IPV6_AH: parse_ipv6_ah; \
   IPPROTO_IPV6_NOHDR: accept;

#define UDP_TUNNEL_PORTS \
      1701: parse_l2tp; \
      1723: parse_pptp; \
      2123: parse_gtp; \
      2152: parse_gtp; \
      3386: parse_gtp; \
      3544: parse_teredo; \
      4789: parse_vxlan; \
      6081: parse_genv;


parser prs(packet_in packet, out headers_s headers)
{
   etherip_h etherip;
   ieee802_1q_h vlan_q;
   ieee802_1q_h vlan_ad;
   ieee802_1ah_h vlan_ah;
   mpls_h mpls;
   eompls_h eompls;
   trill_h trill;
   pppoe_h pppoe;
   gre_h gre;
   gre_sre_h gre_sre;
   l2tp_h l2tp;
   vxlan_h vxlan;
   genv_h genv;
   gtp_v0_h gtp_v0;
   gtp_v1_h gtp_v1;
   gtp_v2_h gtp_v2;
   gtp_v1_next_hdr_h gtp_v1_next_hdr;
   teredo_auth_h teredo_auth;
   teredo_origin_h teredo_origin;
   pptp_uncomp_proto_h pptp_uncomp_proto;
   pptp_comp_proto_h pptp_comp_proto;
   ipv6_hop_opt_h ipv6_hop_opt;
   ipv6_dst_opt_h ipv6_dst_opt;
   ipv6_routing_h ipv6_routing;
   ipv6_fragment_h ipv6_fragment;
   ipv6_ah_h ipv6_ah;

   bit<16> udp_src_port;

   state start {
      transition parse_ethernet;
   }

   state parse_ethernet {
      packet.extract(headers.eth);

      transition select(headers.eth.ethertype) {
         ETHERTYPE_IPV4: parse_ipv4;
         ETHERTYPE_IPV6: parse_ipv6;
         ETHERTYPE_MPLS_UNICAST: parse_mpls;
         ETHERTYPE_MPLS_MULTICAST: parse_mpls;
         ETHERTYPE_8021Q: parse_vlan_q;
         ETHERTYPE_8021AD: parse_vlan_ad;
         ETHERTYPE_8021AH: parse_vlan_ah;
         ETHERTYPE_TRILL: parse_trill;
         ETHERTYPE_PPP_SESSION: parse_pppoe;
         ETHERTYPE_PPP_DISCOVERY: reject;
         default: reject;
      }
   }

   state parse_vlan_q {
      packet.extract(vlan_q);

      transition select(vlan_q.ethertype) {
         ETHERTYPE_IPV4: parse_ipv4;
         ETHERTYPE_IPV6: parse_ipv6;
         ETHERTYPE_MPLS_UNICAST: parse_mpls;
         ETHERTYPE_MPLS_MULTICAST: parse_mpls;
         ETHERTYPE_8021Q: parse_vlan_q;
         ETHERTYPE_8021AD: parse_vlan_ad;
         ETHERTYPE_TRILL: parse_trill;
         ETHERTYPE_PPP_SESSION: parse_pppoe;
         ETHERTYPE_PPP_DISCOVERY: reject;
         default: reject;
      }
   }

   state parse_vlan_ad {
      packet.extract(vlan_ad);

      transition select(vlan_ad.ethertype) {
         ETHERTYPE_IPV4: parse_ipv4;
         ETHERTYPE_IPV6: parse_ipv6;
         ETHERTYPE_MPLS_UNICAST: parse_mpls;
         ETHERTYPE_MPLS_MULTICAST: parse_mpls;
         ETHERTYPE_8021Q: parse_vlan_q;
         ETHERTYPE_8021AH: parse_vlan_ah;
         ETHERTYPE_TRILL: parse_trill;
         ETHERTYPE_PPP_SESSION: parse_pppoe;
         ETHERTYPE_PPP_DISCOVERY: reject;
         default: reject;
      }
   }

   state parse_vlan_ah {
      packet.extract(vlan_ah);

      transition parse_ethernet;
   }

   state parse_trill {
      packet.extract(trill);

      /* Skip options. */
      packet.advance((bit<32>)trill.op_len * 32);

      transition parse_ethernet;
   }

   state parse_mpls {
      packet.extract(mpls);
      transition select(mpls.bos) {
         0: parse_mpls;
         1: parse_mpls_end;
         default: reject;
      }
   }

   state parse_mpls_end {
      transition select(packet.lookahead<bit<4>>()) {
         4: parse_ipv4;
         6: parse_ipv6;
         0: parse_eompls;
         default: reject;
      }
   }

   state parse_eompls {
      packet.extract(eompls);

      transition parse_ethernet;
   }

   state parse_pppoe {
      packet.extract(pppoe);

      transition select(pppoe.code) {
         0: parse_pptp;
         default: reject;
      }
   }

   state parse_pptp {
      transition select(packet.lookahead<bit<16>>()) {
         0xFF03: parse_pptp_uncomp_addr_cntrl;
         default: parse_pptp_comp_addr_cntrl;
      }
   }

   state parse_pptp_uncomp_addr_cntrl {
      /* Skip address and control fields. */
      packet.advance(16);

      transition select(packet.lookahead<bit<8>>() & 0x01) {
         0: parse_pptp_uncomp_proto;
         1: parse_pptp_comp_proto;
         default: reject;
      }
   }

   state parse_pptp_comp_addr_cntrl {
      transition select(packet.lookahead<bit<8>>() & 0x01) {
         0: parse_pptp_uncomp_proto;
         1: parse_pptp_comp_proto;
         default: reject;
      }
   }

   state parse_pptp_uncomp_proto {
      packet.extract(pptp_uncomp_proto);

      transition select((bit<16>)pptp_uncomp_proto.proto) {
         PPP_IPV4: parse_ipv4;
         PPP_IPV6: parse_ipv6;
         PPP_COMP: accept;
         PPP_CONTROL: accept;
         default: reject;
      }
   }

   state parse_pptp_comp_proto {
      packet.extract(pptp_comp_proto);

      transition select((bit<16>)pptp_comp_proto.proto) {
         PPP_IPV4: parse_ipv4;
         PPP_IPV6: parse_ipv6;
         PPP_COMP: accept;
         PPP_CONTROL: accept;
         default: reject;
      }
   }

   state parse_ipv4 {
      packet.extract(headers.ipv4);

      /* Skip IP options. */
      packet.advance((bit<32>)(((int<32>)(bit<32>)headers.ipv4.ihl - (int<32>)5) * 32));

      transition select(headers.ipv4.protocol) {
         IPPROTO_TCP: parse_tcp;
         IPPROTO_UDP: parse_udp;
         IPPROTO_ICMP: parse_icmp;
         IPPROTO_GRE: parse_gre;
         IPPROTO_IPIP: parse_ipv4;
         IPPROTO_IPV6: parse_ipv6;
         IPPROTO_ETHERIP: parse_etherip;
         IPPROTO_MPLS: parse_mpls;
         default: accept;
      }
   }

   state parse_ipv6 {
      packet.extract(headers.ipv6);

      transition select(headers.ipv6.next_hdr) {
         SWITCH_IPV6
         default: accept;
      }
   }

   state parse_ipv6_hop_opt {
      packet.extract(ipv6_hop_opt);

      /* Skip options. */
      packet.advance((bit<32>)ipv6_hop_opt.hdr_len * 64 + 48);

      headers.ipv6.next_hdr = ipv6_hop_opt.next_hdr;

      transition select(ipv6_hop_opt.next_hdr) {
         SWITCH_IPV6
         default: reject;
      }
   }

   state parse_ipv6_dst_opt {
      packet.extract(ipv6_dst_opt);

      /* Skip options. */
      packet.advance((bit<32>)ipv6_dst_opt.hdr_len * 64 + 48);

      headers.ipv6.next_hdr = ipv6_dst_opt.next_hdr;

      transition select(ipv6_dst_opt.next_hdr) {
         SWITCH_IPV6
         default: reject;
      }
   }

   state parse_ipv6_routing {
      packet.extract(ipv6_routing);

      /* Skip data. */
      packet.advance((bit<32>)ipv6_routing.hdr_len * 64 + 48);

      headers.ipv6.next_hdr = ipv6_routing.next_hdr;

      transition select(ipv6_routing.next_hdr) {
         SWITCH_IPV6
         default: reject;
      }
   }

   state parse_ipv6_fragment {
      packet.extract(ipv6_fragment);

      headers.ipv6.next_hdr = ipv6_fragment.next_hdr;

      transition accept;
   }

   state parse_ipv6_ah {
      packet.extract(ipv6_ah);

      packet.advance((bit<32>)ipv6_ah.len * 32);

      headers.ipv6.next_hdr = ipv6_ah.next_hdr;

      transition select(ipv6_ah.next_hdr) {
         SWITCH_IPV6
         default: reject;
      }
   }

   state parse_etherip {
      packet.extract(etherip);

      transition select(etherip.version) {
         3: parse_ethernet;
         default: reject;
      }
   }

   state parse_gre {
      packet.extract(gre);

      transition select(gre.ver) {
         0: parse_gre_v0;
         1: parse_gre_v1;
         default: reject;
      }
   }

   state parse_gre_v0 {
      /* Skip optional fields. */
      packet.advance((((bit<32>)gre.C | (bit<32>)gre.R) * 32));
      packet.advance(((bit<32>)gre.K * 32));
      packet.advance(((bit<32>)gre.S * 32));

      transition select(gre.R) {
         1: parse_gre_sre;
         0: parse_gre_v0_fin;
         default: reject;
      }
   }

   state parse_gre_v0_fin {
      transition select(gre.proto) {
         GRE_IPV4: parse_ipv4;
         GRE_IPV6: parse_ipv6;
         GRE_PPP: parse_pptp;
         GRE_ETH: parse_ethernet;
         ETHERTYPE_MPLS_UNICAST: parse_mpls;
         ETHERTYPE_MPLS_MULTICAST: parse_mpls;
         default: reject;
      }
   }

   state parse_gre_v1 {
      /* Skip fields. */
      packet.advance(32);
      packet.advance((bit<32>)gre.S * 32);
      packet.advance((bit<32>)gre.A * 32);

      transition select(gre.proto) {
         GRE_IPV4: parse_ipv4;
         GRE_IPV6: parse_ipv6;
         GRE_PPP: parse_pptp;
         GRE_ETH: parse_ethernet;
         ETHERTYPE_MPLS_UNICAST: parse_mpls;
         ETHERTYPE_MPLS_MULTICAST: parse_mpls;
         default: reject;
      }
   }

   state parse_gre_sre {
      packet.extract(gre_sre);
      packet.advance((bit<32>)gre_sre.length);

      transition select(gre_sre.length) {
         0: parse_gre_v0_fin;
         default: parse_gre_sre;
      }
   }

   state parse_l2tp {
      packet.extract(l2tp);

      transition select(l2tp.version) {
         2: parse_l2tp_v2;
         default: reject;
      }
   }

   state parse_l2tp_v2 {
      packet.advance((bit<32>)l2tp.length * 16);
      packet.advance((bit<32>)32);
      packet.advance((bit<32>)l2tp.seq * 32);
      packet.advance((bit<32>)l2tp.offset * (bit<32>)(packet.lookahead<bit<16>>()) * 8);
      packet.advance((bit<32>)l2tp.offset * 16);

      transition select(l2tp.type) {
         0: parse_pptp;
         default: reject;
      }
   }

   state parse_gtp {
      transition select(packet.lookahead<bit<3>>()) {
         0: parse_gtp_v0;
         1: parse_gtp_v1;
         2: parse_gtp_v2;
         default: reject;
      }
   }

   state parse_gtp_v0 {
      packet.extract(gtp_v0);

      transition select(gtp_v0.type) {
         GTP_TPDU: parse_gtp_fin;
         default: reject;
      }
   }

   state parse_gtp_v1 {
      packet.extract(gtp_v1);

      transition select((bit<32>)gtp_v1.E | (bit<32>)gtp_v1.S | (bit<32>)gtp_v1.PN) {
         1: parse_gtp_v1_opt;
         0: parse_gtp_v1_check_type;
         default: reject;
      }
   }

   state parse_gtp_v1_check_type {
      transition select(gtp_v1.type) {
         GTP_TPDU: parse_gtp_fin;
         default: reject;
      }
   }

   state parse_gtp_v1_opt {
      /* Skip seq num and N-PDU num optional fields. */
      packet.advance(24);

      transition select(gtp_v1.E) {
         1: parse_gtp_v1_next_hdr;
         0: parse_gtp_v1_skip_nexthdr;
         default: reject;
      }
   }

   state parse_gtp_v1_next_hdr {
      /* Skip length and contents of the extension header. */
      packet.advance((bit<32>)((int<32>)((bit<32>)(packet.lookahead<bit<8>>()) * 32) - (int<32>)8));

      packet.extract(gtp_v1_next_hdr);
      transition select(gtp_v1_next_hdr.next_hdr) {
         0: parse_gtp_v1_check_type;
         default: parse_gtp_v1_next_hdr;
      }
   }

   state parse_gtp_v1_skip_nexthdr {
      packet.advance(8);

      transition select(gtp_v1.type) {
         GTP_TPDU: parse_gtp_fin;
         default: reject;
      }
   }

   state parse_gtp_v2 {
      packet.extract(gtp_v2);

      /* Skip optional fields. */
      packet.advance((bit<32>)gtp_v2.TEID_flag * 32);

      /* Skip sequnce num and spare bits. */
      packet.advance(32);

      transition select(gtp_v2.type) {
         GTP_TPDU: parse_gtp_fin;
         default: reject;
      }
   }

   state parse_gtp_fin {
      transition select(packet.lookahead<bit<4>>()) {
         4: parse_ipv4;
         6: parse_ipv6;
         // TODO parse PPP ???
         default: reject;
      }
   }

   state parse_teredo {
      transition select(packet.lookahead<bit<4>>()) {
         6: parse_ipv6;
         0: parse_teredo_hdr;
         default: reject;
      }
   }

   state parse_teredo_hdr {
      transition select(packet.lookahead<bit<16>>()) {
         0x0001: parse_teredo_auth_hdr;
         0x0000: parse_teredo_origin_hdr;
         default: reject;
      }
   }

   state parse_teredo_auth_hdr {
      packet.extract(teredo_auth);

      /* Skip auth, id, confirmation byte and nonce. */
      packet.advance((bit<32>)teredo_auth.id_len * 8 + (bit<32>)teredo_auth.auth_len * 8 + 72);

      transition select(packet.lookahead<bit<4>>()) {
         6: parse_ipv6;
         0: parse_teredo_hdr;
         default: reject;
      }
   }

   state parse_teredo_origin_hdr {
      packet.extract(teredo_origin);

      transition select(packet.lookahead<bit<4>>()) {
         6: parse_ipv6;
         0: parse_teredo_hdr;
         default: reject;
      }
   }

   state parse_vxlan {
      packet.extract(vxlan);

      transition parse_ethernet;
   }

   state parse_genv {
      packet.extract(genv);

      packet.advance((bit<32>)genv.opt_len * 32);

      transition select(genv.proto) {
         GENV_ETH: parse_ethernet;
         ETHERTYPE_MPLS_MULTICAST: parse_mpls;
         ETHERTYPE_MPLS_UNICAST: parse_mpls;
         default: reject;
      }
   }

   state parse_tcp {
      packet.extract(headers.tcp);

      /* Skip TCP options. */
      packet.advance((bit<32>)(((int<32>)(bit<32>)headers.tcp.data_offset - (int<32>)5) * 32));

      transition parse_payload;
   }

   state parse_udp {
      packet.extract(headers.udp);

      udp_src_port = headers.udp.src_port;

      transition select(headers.udp.dst_port) {
         UDP_TUNNEL_PORTS
         default: parse_udp_2;
      }
   }

   state parse_udp_2 {
      transition select(udp_src_port) {
         UDP_TUNNEL_PORTS
         default: parse_payload;
      }
   }

   state parse_icmp {
      packet.extract(headers.icmp);
      transition accept;
   }

   state parse_icmp6 {
      packet.extract(headers.icmp6);
      transition accept;
   }

   state parse_payload {
      /* Get position of the payload. */
      packet.extract(headers.payload);
      transition accept;
   }
}

#endif // _PARSER_P4_
