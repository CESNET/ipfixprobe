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

#ifndef _HEADERS_P4_
#define _HEADERS_P4_

#define ETHERTYPE_8021Q          0x8100
#define ETHERTYPE_8021AD         0x88A8
#define ETHERTYPE_8021AH         0x88E7
#define ETHERTYPE_MPLS_UNICAST   0x8847
#define ETHERTYPE_MPLS_MULTICAST 0x8848
#define ETHERTYPE_IPV4           0x0800
#define ETHERTYPE_IPV6           0x86DD
#define ETHERTYPE_TRILL          0x22F3
#define ETHERTYPE_PPP_DISCOVERY  0x8863
#define ETHERTYPE_PPP_SESSION    0x8864

#define IPPROTO_ICMP       1
#define IPPROTO_IPIP       4
#define IPPROTO_TCP        6
#define IPPROTO_UDP        17
#define IPPROTO_IPV6       41
#define IPPROTO_GRE        47
#define IPPROTO_IPSEC_ESP  50
#define IPPROTO_IPSEC_AH   51
#define IPPROTO_ICMPV6     58
#define IPPROTO_ETHERIP    97
#define IPPROTO_L2TP       115
#define IPPROTO_SCTP       132
#define IPPROTO_MPLS       137

#define IPPROTO_IPV6_HOP_OPT  0
#define IPPROTO_IPV6_DST_OPT  60
#define IPPROTO_IPV6_ROUTING  43
#define IPPROTO_IPV6_FRAGMENT 44
#define IPPROTO_IPV6_AH       51
#define IPPROTO_IPV6_ESP      50
#define IPPROTO_IPV6_MOBILITY 135
#define IPPROTO_IPV6_NOHDR    59

#define PPP_IPV4     0x0021
#define PPP_IPV6     0x0057
#define PPP_COMP     0x00FD
#define PPP_CONTROL  0xC021

#define GRE_IPV4  0x0800
#define GRE_IPV6  0x86DD
#define GRE_PPP   0x880B
#define GRE_ETH   0x6558

#define GENV_ETH 0x6558

#define GTP_ECHO_REQ    0x01
#define GTP_ECHO_RESP   0x02
#define GTP_PDP_REQ     0x10
#define GTP_PDP_RESP    0x11
#define GTP_TPDU        0xFF

#define IGMP_MEMBER_QUERY  0x11
#define IGMP_V1            0x12
#define IGMP_V2            0x16
#define IGMP_V3            0x22
#define IGMP_LEAVE_G       0x17

#define GENV_OPT_A 0x1
#define GENV_OPT_B 0x2
#define GENV_OPT_C 0x3

header ethernet_h {
   bit<48> dst_addr;
   bit<48> src_addr;
   bit<16> ethertype;
}

header ieee802_1q_h {
   bit<3> pcp;
   bit<1> cfi;
   bit<12> vid;
   bit<16> ethertype;
}

header ieee802_1ah_h {
   bit<3> prio;
   bit<1> drop;
   bit<1> nca;
   bit<1> res1;
   bit<2> res2;
   bit<24> isid;
}

header etherip_h {
   bit<4> version;
   bit<12> reserved;
}

header mpls_h {
   bit<20> label;
   bit<3> tc;
   bit<1> bos;
   bit<8> ttl;
}

header eompls_h {
   bit<4> zero;
   bit<12> res;
   bit<16> seq_num;
}

header trill_h {
   bit<2> version;
   bit<2> res;
   bit<1> m;
   bit<5> op_len;
   bit<6> hop_cnt;
   bit<16> egress_nick;
   bit<16> ingress_nick;
   // options varlen
}

header pppoe_h {
   bit<4> version;
   bit<4> type;
   bit<8> code;
   bit<16> sid;
   bit<16> len;
}

header pptp_comp_h {
   bit<16> proto;
}

header pptp_uncomp_h {
   bit<8> address;
   bit<8> cntrl;
   bit<16> proto;
}

header pptp_uncomp_proto_h {
   bit<16> proto;
}

header pptp_comp_proto_h {
   bit<8> proto;
}

header ipv4_h {
   bit<4> version;
   bit<4> ihl;
   bit<8> diffserv;
   bit<16> total_len;
   bit<16> identification;
   bit<3> flags;
   bit<13> frag_offset;
   bit<8> ttl;
   bit<8> protocol;
   bit<16> hdr_checksum;
   bit<32> src_addr;
   bit<32> dst_addr;
}

header ipv6_h {
   bit<4> version;
   bit<8> traffic_class;
   bit<20> flow_label;
   bit<16> payload_len;
   bit<8> next_hdr;
   bit<8> hop_limit;
   bit<128> src_addr;
   bit<128> dst_addr;
}

header ipv6_hop_opt_h {
   bit<8> next_hdr;
   bit<8> hdr_len;
   // options varlen
}

header ipv6_dst_opt_h {
   bit<8> next_hdr;
   bit<8> hdr_len;
   // options varlen
}

header ipv6_routing_h {
   bit<8> next_hdr;
   bit<8> hdr_len;
   // data varlen
}

header ipv6_fragment_h {
   bit<8> next_hdr;
   bit<8> res1;
   bit<13> frag_offset;
   bit<2> res2;
   bit<1> m;
   bit<32> id;
}

header ipv6_ah_h {
   bit<8> next_hdr;
   bit<8> len;
   bit<16> res;
   bit<32> spi;
   //bit<32> seq_num;
   // icv varlen
}

header gre_h {
   bit<1> C;
   bit<1> R;
   bit<1> K;
   bit<1> S;
   bit<1> s;
   bit<3> recur;
   bit<1> A;
   bit<4> flags;
   bit<3> ver;
   bit<16> proto;
   // type specific fields
}

header gre_sre_h {
   bit<16> addr_family;
   bit<8> offset;
   bit<8> length;
}

header l2f_h {
   bit<1> F;
   bit<1> K;
   bit<1> P;
   bit<1> S;
   bit<8> res;
   bit<1> C;
   bit<3> version;
}

header l2tp_h {
   bit<1> type;
   bit<1> length;
   bit<2> res1;
   bit<1> seq;
   bit<1> res2;
   bit<1> offset;
   bit<1> priority;
   bit<4> res3;
   bit<4> version;
   // optional fields
}

header vxlan_h {
   bit<1> gbp_ext;
   bit<3> res1;
   bit<1> vni_flag;
   bit<4> res2;
   bit<1> dont_learn;
   bit<2> res3;
   bit<1> policy_applied;
   bit<3> res4;
   bit<16> gpolicy_id;
   bit<24> vni;
   bit<8> res5;
}

header sctp_h {
   bit<16> src_port;
   bit<16> dst_port;
   bit<32> verif_tag;
   bit<32> checksum;
}

header icmp_h {
   bit<8> type_;
   bit<8> code;
   bit<16> hdr_checksum;
   bit<32> rest;
}

header icmpv6_h {
   bit<8> type_;
   bit<8> code;
   bit<16> hdr_checksum;
   bit<32> rest;
}

header tcp_h {
   bit<16> src_port;
   bit<16> dst_port;
   bit<32> seq_num;
   bit<32> ack_num;
   bit<4> data_offset;
   bit<4> res;
   bit<8> flags;
   bit<16> window;
   bit<16> checksum;
   bit<16> urgent_ptr;
   // options varlen
}

header udp_h {
   bit<16> src_port;
   bit<16> dst_port;
   bit<16> len;
   bit<16> checksum;
}

header igmp_v2_h {
   bit<8> type;
   bit<8> max_resp_time;
   bit<16> checksum;
   bit<32> group_addr;
}

header igmp_v3_h {
   bit<4> res;
   bit<1> S;
   bit<3> QRV;
   bit<8> QQIC;
   bit<16> N; // number of sources
   // varlen
}

header gtp_v0_h {
   bit<3> version;
   bit<1> proto_type;
   bit<3> res1;
   bit<1> snn;
   bit<8> type;
   bit<16> length;
   bit<16> seq_num;
   bit<16> flow_label;
   bit<8> sndcp_num;
   bit<24> res2;
   bit<64> tid;
}

header gtp_v1_h {
   bit<3> version;
   bit<1> proto_type;
   bit<1> res;
   bit<1> E;
   bit<1> S;
   bit<1> PN;
   bit<8> type;
   bit<16> length;
   bit<32> TEID;
   // optional fields
}

header gtp_v1_next_hdr_h {
   bit<8> next_hdr;
}

header gtp_v2_h {
   bit<3> version;
   bit<1> piggy_flag;
   bit<1> TEID_flag;
   bit<3> spare;
   bit<8> type;
   bit<16> length;
   // optional fields
}

header teredo_auth_h {
   bit<8> zero;
   bit<8> type;
   bit<8> id_len;
   bit<8> auth_len;
   // variable length fields
}

header teredo_origin_h {
   bit<8> zero;
   bit<8> type;
   bit<16> port;
   bit<32> ip;
}

header genv_h {
   bit<2> version;
   bit<6> opt_len;
   bit<1> oam;
   bit<1> critical;
   bit<6> res1;
   bit<16> proto;
   bit<24> vni;
   bit<8> res2;
}

header genv_opt_a_h {
   bit<16> opt_class;
   bit<8> opt_type;
   bit<3> res;
   bit<5> opt_len;
   bit<32> data;
}

header genv_opt_b_h {
   bit<16> opt_class;
   bit<8> opt_type;
   bit<3> res;
   bit<5> opt_len;
   bit<64> data;
}

header genv_opt_c_h {
   bit<16> opt_class;
   bit<8> opt_type;
   bit<3> res;
   bit<5> opt_len;
   bit<32> data;
}

header payload_h {
}

#endif // _HEADERS_P4_
