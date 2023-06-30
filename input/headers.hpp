/**
 * \file headers.hpp
 * \brief Packet parser headers.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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

#ifndef IPXP_INPUT_HEADERS_HPP
#define IPXP_INPUT_HEADERS_HPP

#include <netinet/in.h>
#include <endian.h>

#define ETH_P_8021AD  0x88A8
#define ETH_P_8021AH  0x88E7
#define ETH_P_8021Q   0x8100
#define ETH_P_IP      0x0800
#define ETH_P_IPV6    0x86DD
#define ETH_P_MPLS_UC 0x8847
#define ETH_P_MPLS_MC 0x8848
#define ETH_P_PPP_SES 0x8864

#define ETH_ALEN 6
#define ARPHRD_ETHER 1

namespace ipxp {


struct ip6_frag {
   uint8_t ip_proto;
   uint8_t reserved;
   uint16_t frag_off;
// this is value in octets, so it doesn't need to be shifted
#define IPV6_FRAGMENT_OFFSET 0xFFF8
#define IPV6_MORE_FRAGMENTS 0x1
   uint32_t frag_id;
} __attribute__((packed));

// Copied protocol headers from netinet/* files, which may not be present on other platforms

struct ethhdr {
   unsigned char  h_dest[ETH_ALEN]; /* destination eth addr */
   unsigned char  h_source[ETH_ALEN];  /* source ether addr */
   uint16_t      h_proto;    /* packet type ID field */
} __attribute__((packed));

struct iphdr
{
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
   unsigned int ihl:4;
   unsigned int version:4;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
   unsigned int version:4;
   unsigned int ihl:4;
#else
# error  "Please fix <endian.h>"
#endif
   uint8_t tos;
   uint16_t tot_len;
   uint16_t id;
   uint16_t frag_off;
   uint8_t ttl;
   uint8_t protocol;
   uint16_t check;
   uint32_t saddr;
   uint32_t daddr;
   /*The options start here. */
};

struct ip6_hdr
{
   union
   {
      struct ip6_hdrctl
      {
         uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                     20 bits flow-ID */
         uint16_t ip6_un1_plen;   /* payload length */
         uint8_t  ip6_un1_nxt;    /* next header */
         uint8_t  ip6_un1_hlim;   /* hop limit */
      } ip6_un1;
      uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
   } ip6_ctlun;
   struct in6_addr ip6_src;      /* source address */
   struct in6_addr ip6_dst;      /* destination address */
};

struct ip6_ext
{
   uint8_t  ip6e_nxt;     /* next header.  */
   uint8_t  ip6e_len;     /* length in units of 8 octets.  */
};

struct ip6_rthdr
{
   uint8_t  ip6r_nxt;     /* next header */
   uint8_t  ip6r_len;     /* length in units of 8 octets */
   uint8_t  ip6r_type;    /* routing type */
   uint8_t  ip6r_segleft; /* segments left */
   /* followed by routing type specific data */
};

struct tcphdr
{
   __extension__ union
   {
      struct
      {
         uint16_t th_sport;   /* source port */
         uint16_t th_dport;   /* destination port */
         uint32_t th_seq;      /* sequence number */
         uint32_t th_ack;      /* acknowledgement number */
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
         uint8_t th_x2:4;  /* (unused) */
         uint8_t th_off:4; /* data offset */
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
         uint8_t th_off:4; /* data offset */
         uint8_t th_x2:4;  /* (unused) */
# else
#  error  "Please fix <endian.h>"
# endif
         uint8_t th_flags;
# define TH_FIN   0x01
# define TH_SYN   0x02
# define TH_RST   0x04
# define TH_PUSH  0x08
# define TH_ACK   0x10
# define TH_URG   0x20
         uint16_t th_win;  /* window */
         uint16_t th_sum;  /* checksum */
         uint16_t th_urp;  /* urgent pointer */
      };
      struct
      {
         uint16_t source;
         uint16_t dest;
         uint32_t seq;
         uint32_t ack_seq;
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
         uint16_t res1:4;
         uint16_t doff:4;
         uint16_t fin:1;
         uint16_t syn:1;
         uint16_t rst:1;
         uint16_t psh:1;
         uint16_t ack:1;
         uint16_t urg:1;
         uint16_t res2:2;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
         uint16_t doff:4;
         uint16_t res1:4;
         uint16_t res2:2;
         uint16_t urg:1;
         uint16_t ack:1;
         uint16_t psh:1;
         uint16_t rst:1;
         uint16_t syn:1;
         uint16_t fin:1;
# else
#  error "Please fix <endian.h>"
# endif
         uint16_t window;
         uint16_t check;
         uint16_t urg_ptr;
      };
   };
};

struct udphdr
{
   __extension__ union
   {
      struct
      {
         uint16_t uh_sport;   /* source port */
         uint16_t uh_dport;   /* destination port */
         uint16_t uh_ulen;    /* udp length */
         uint16_t uh_sum;     /* udp checksum */
      };
      struct
      {
         uint16_t source;
         uint16_t dest;
         uint16_t len;
         uint16_t check;
      };
   };
};

struct icmphdr
{
   uint8_t type;      /* message type */
   uint8_t code;      /* type sub-code */
   uint16_t checksum;
   union
   {
      struct
      {
         uint16_t id;
         uint16_t sequence;
      } echo;       /* echo datagram */
      uint32_t   gateway; /* gateway address */
      struct
      {
         uint16_t __glibc_reserved;
         uint16_t mtu;
      } frag;       /* path mtu discovery */
   } un;
};

struct icmp6_hdr
{
   uint8_t     icmp6_type;   /* type field */
   uint8_t     icmp6_code;   /* code field */
   uint16_t    icmp6_cksum;  /* checksum field */
   union
   {
      uint32_t  icmp6_un_data32[1]; /* type-specific field */
      uint16_t  icmp6_un_data16[2]; /* type-specific field */
      uint8_t   icmp6_un_data8[4];  /* type-specific field */
   } icmp6_dataun;
};

struct __attribute__((packed)) trill_hdr {
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
   uint8_t op_len1:3;
   uint8_t m:1;
   uint8_t res:2;
   uint8_t version:2;
   uint8_t hop_cnt:6;
   uint8_t op_len2:2;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
   uint8_t version:2;
   uint8_t res:2;
   uint8_t m:1;
   uint8_t op_len1:3;
   uint8_t op_len2:2;
   uint8_t hop_cnt:6;
# else
#  error  "Please fix <endian.h>"
# endif
   uint16_t egress_nick;
   uint16_t ingress_nick;
};

struct __attribute__((packed)) pppoe_hdr {
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
   uint8_t type:4;
   uint8_t version:4;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
   uint8_t version:4;
   uint8_t type:4;
# else
#  error  "Please fix <endian.h>"
# endif
   uint8_t code;
   uint16_t sid;
   uint16_t length;
};

}
#endif /* IPXP_INPUT_HEADERS_HPP */
