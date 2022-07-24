/**
 * \file parser.cpp
 * \brief Packet parser functions
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

#include <config.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sys/types.h>

#include "parser.hpp"
#include "headers.hpp"
#include <ipfixprobe/packet.hpp>

namespace ipxp {

//#define DEBUG_PARSER

#ifdef DEBUG_PARSER
// Print debug message if debugging is allowed.
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
// Process code if debugging is allowed.
#define DEBUG_CODE(code) code
static uint32_t s_total_pkts = 0;
#else
#define DEBUG_MSG(format, ...)
#define DEBUG_CODE(code)
#endif

/**
 * \brief Parse specific fields from ETHERNET frame header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_eth_hdr(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct ethhdr *eth = (struct ethhdr *) data_ptr;
   if (sizeof(struct ethhdr) > data_len) {
      throw "Parser detected malformed packet";
   }
   uint16_t hdr_len = sizeof(struct ethhdr);
   uint16_t ethertype = ntohs(eth->h_proto);

   DEBUG_MSG("Ethernet header:\n");
#ifndef __CYGWIN__
   DEBUG_MSG("\tDest mac:\t%s\n",         ether_ntoa((struct ether_addr *) eth->h_dest));
   DEBUG_MSG("\tSrc mac:\t%s\n",          ether_ntoa((struct ether_addr *) eth->h_source));
#else
   DEBUG_CODE(
      char src_mac[18]; // ether_ntoa missing on some platforms
      char dst_mac[18];
      uint8_t *p = (uint8_t *) eth->h_source;
      snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
      p = (uint8_t *) eth->h_dest;
      snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
   );
   DEBUG_MSG("\tDest mac:\t%s\n",         dst_mac);
   DEBUG_MSG("\tSrc mac:\t%s\n",          src_mac);
#endif
   DEBUG_MSG("\tEthertype:\t%#06x\n",     ethertype);

   memcpy(pkt->dst_mac, eth->h_dest, 6);
   memcpy(pkt->src_mac, eth->h_source, 6);

   if (ethertype == ETH_P_8021AD) {
      if (4 > data_len - hdr_len) {
         throw "Parser detected malformed packet";
      }
      DEBUG_CODE(uint16_t vlan = ntohs(*(uint16_t *) (data_ptr + hdr_len)));
      DEBUG_MSG("\t802.1ad field:\n");
      DEBUG_MSG("\t\tPriority:\t%u\n",    ((vlan & 0xE000) >> 12));
      DEBUG_MSG("\t\tCFI:\t\t%u\n",       ((vlan & 0x1000) >> 11));
      DEBUG_MSG("\t\tVLAN:\t\t%u\n",      (vlan & 0x0FFF));

      hdr_len += 4;
      ethertype = ntohs(*(uint16_t *) (data_ptr + hdr_len - 2));
      DEBUG_MSG("\t\tEthertype:\t%#06x\n", ethertype);
   }
   while (ethertype == ETH_P_8021Q) {
      if (4 > data_len - hdr_len) {
         throw "Parser detected malformed packet";
      }
      DEBUG_CODE(uint16_t vlan = ntohs(*(uint16_t *) (data_ptr + hdr_len)));
      DEBUG_MSG("\t802.1q field:\n");
      DEBUG_MSG("\t\tPriority:\t%u\n",    ((vlan & 0xE000) >> 12));
      DEBUG_MSG("\t\tCFI:\t\t%u\n",       ((vlan & 0x1000) >> 11));
      DEBUG_MSG("\t\tVLAN:\t\t%u\n",      (vlan & 0x0FFF));

      hdr_len += 4;
      ethertype = ntohs(*(uint16_t *) (data_ptr + hdr_len - 2));
      DEBUG_MSG("\t\tEthertype:\t%#06x\n", ethertype);
   }

   pkt->ethertype = ethertype;

   return hdr_len;
}

#ifdef WITH_PCAP
/**
 * \brief Parse specific fields from SLL frame header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_sll(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct sll_header *sll = (struct sll_header *) data_ptr;
   if (sizeof(struct sll_header) > data_len) {
      throw "Parser detected malformed packet";
   }

   DEBUG_MSG("SLL header:\n");
   DEBUG_MSG("\tPacket type:\t%u\n",  ntohs(sll->sll_pkttype));
   DEBUG_MSG("\tHA type:\t%u\n", ntohs(sll->sll_hatype));
   DEBUG_MSG("\tHA len:\t\t%u\n",  ntohs(sll->sll_halen));
   DEBUG_CODE(
      DEBUG_MSG("\tAddress:\t");
      for (int i = 0; i < SLL_ADDRLEN; i++) {
         DEBUG_MSG("%02x ", sll->sll_addr[i]);
      }
      DEBUG_MSG("\n");
   );
   DEBUG_MSG("\tProtocol:\t%u\n",     ntohs(sll->sll_protocol));

   if (ntohs(sll->sll_hatype) == ARPHRD_ETHER) {
      memcpy(pkt->src_mac, sll->sll_addr, 6);
   } else {
      memset(pkt->src_mac, 0, sizeof(pkt->src_mac));
   }
   memset(pkt->dst_mac, 0, sizeof(pkt->dst_mac));
   pkt->ethertype = ntohs(sll->sll_protocol);
   return sizeof(struct sll_header);
}

# ifdef DLT_LINUX_SLL2
inline uint16_t parse_sll2(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct sll2_header *sll = (struct sll2_header *) data_ptr;
   if (sizeof(struct sll2_header) > data_len) {
      throw "Parser detected malformed packet";
   }

   DEBUG_MSG("SLL2 header:\n");
   DEBUG_MSG("\tPacket type:\t%u\n",  ntohs(sll->sll2_pkttype));
   DEBUG_MSG("\tHA type:\t%u\n", ntohs(sll->sll2_hatype));
   DEBUG_MSG("\tHA len:\t\t%u\n",  ntohs(sll->sll2_halen));
   DEBUG_MSG("\tinterface index:\t\t%u\n",  ntohl(sll->sll2_if_index));
   DEBUG_CODE(
      DEBUG_MSG("\tAddress:\t");
      for (int i = 0; i < SLL_ADDRLEN; i++) {
         DEBUG_MSG("%02x ", sll->sll2_addr[i]);
      }
      DEBUG_MSG("\n");
   );
   DEBUG_MSG("\tProtocol:\t%u\n",     ntohs(sll->sll2_protocol));

   if (ntohs(sll->sll2_hatype) == ARPHRD_ETHER) {
      memcpy(pkt->src_mac, sll->sll2_addr, 6);
   } else {
      memset(pkt->src_mac, 0, sizeof(pkt->src_mac));
   }
   memset(pkt->dst_mac, 0, sizeof(pkt->dst_mac));
   pkt->ethertype = ntohs(sll->sll2_protocol);
   return sizeof(struct sll2_header);
}
# endif /* DLT_LINUX_SLL2 */
#endif /* WITH_PCAP */


/**
 * \brief Parse specific fields from TRILL.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_trill(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct trill_hdr *trill = (struct trill_hdr *) data_ptr;
   if (sizeof(struct trill_hdr) > data_len) {
      throw "Parser detected malformed packet";
   }
   uint8_t op_len = ((trill->op_len1 << 2) | trill->op_len2);
   uint8_t op_len_bytes = op_len * 4;

   DEBUG_MSG("TRILL header:\n");
   DEBUG_MSG("\tHDR version:\t%u\n",         trill->version);
   DEBUG_MSG("\tRES:\t\t%u\n",               trill->res);
   DEBUG_MSG("\tM:\t\t%u\n",                 trill->m);
   DEBUG_MSG("\tOP length:\t%u (%u B)\n",    op_len, op_len_bytes);
   DEBUG_MSG("\tHop cnt:\t%u\n",             trill->hop_cnt);
   DEBUG_MSG("\tEgress nick:\t%u\n",         ntohs(trill->egress_nick));
   DEBUG_MSG("\tIngress nick:\t%u\n",        ntohs(trill->ingress_nick));

   return sizeof(trill_hdr) + op_len_bytes;
}

/**
 * \brief Parse specific fields from IPv4 header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_ipv4_hdr(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct iphdr *ip = (struct iphdr *) data_ptr;
   if (sizeof(struct iphdr) > data_len) {
      throw "Parser detected malformed packet";
   }

   pkt->ip_version = IP::v4;
   pkt->ip_proto = ip->protocol;
   pkt->ip_tos = ip->tos;
   pkt->ip_len = ntohs(ip->tot_len);
   pkt->ip_payload_len = pkt->ip_len - (ip->ihl << 2);
   pkt->ip_ttl = ip->ttl;
   pkt->ip_flags = (ntohs(ip->frag_off) & 0xE000) >> 13;
   pkt->src_ip.v4 = ip->saddr;
   pkt->dst_ip.v4 = ip->daddr;

   DEBUG_MSG("IPv4 header:\n");
   DEBUG_MSG("\tHDR version:\t%u\n",   ip->version);
   DEBUG_MSG("\tHDR length:\t%u\n",    ip->ihl);
   DEBUG_MSG("\tTOS:\t\t%u\n",         ip->tos);
   DEBUG_MSG("\tTotal length:\t%u\n",  ntohs(ip->tot_len));
   DEBUG_MSG("\tID:\t\t%#x\n",         ntohs(ip->id));
   DEBUG_MSG("\tFlags:\t\t%#x\n",      ((ntohs(ip->frag_off) & 0xE000) >> 13));
   DEBUG_MSG("\tFrag off:\t%#x\n",     (ntohs(ip->frag_off) & 0x1FFF));
   DEBUG_MSG("\tTTL:\t\t%u\n",         ip->ttl);
   DEBUG_MSG("\tProtocol:\t%u\n",      ip->protocol);
   DEBUG_MSG("\tChecksum:\t%#06x\n",   ntohs(ip->check));
   DEBUG_MSG("\tSrc addr:\t%s\n",      inet_ntoa(*(struct in_addr *) (&ip->saddr)));
   DEBUG_MSG("\tDest addr:\t%s\n",     inet_ntoa(*(struct in_addr *) (&ip->daddr)));

   return (ip->ihl << 2);
}

/**
 * \brief Skip IPv6 extension headers.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Length of headers in bytes.
 */
uint16_t skip_ipv6_ext_hdrs(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct ip6_ext *ext = (struct ip6_ext *) data_ptr;
   uint8_t next_hdr = pkt->ip_proto;
   uint16_t hdrs_len = 0;

   /* Skip extension headers... */
   while (1) {
      if ((int)sizeof(struct ip6_ext) > data_len - hdrs_len) {
         throw "Parser detected malformed packet";
      }
      if (next_hdr == IPPROTO_HOPOPTS ||
          next_hdr == IPPROTO_DSTOPTS) {
         hdrs_len += (ext->ip6e_len << 3) + 8;
      } else if (next_hdr == IPPROTO_ROUTING) {
         struct ip6_rthdr *rt = (struct ip6_rthdr *) (data_ptr + hdrs_len);
         hdrs_len += (rt->ip6r_len << 3) + 8;
      } else if (next_hdr == IPPROTO_AH) {
         hdrs_len += (ext->ip6e_len << 2) - 2;
      } else if (next_hdr == IPPROTO_FRAGMENT) {
         hdrs_len += 8;
      } else {
         break;
      }
      DEBUG_MSG("\tIPv6 extension header:\t%u\n", next_hdr);
      DEBUG_MSG("\t\tLength:\t%u\n", ext->ip6e_len);

      next_hdr = ext->ip6e_nxt;
      ext = (struct ip6_ext *) (data_ptr + hdrs_len);
      pkt->ip_proto = next_hdr;
   }

   pkt->ip_payload_len -= hdrs_len;
   return hdrs_len;
}

/**
 * \brief Parse specific fields from IPv6 header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_ipv6_hdr(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct ip6_hdr *ip6 = (struct ip6_hdr *) data_ptr;
   uint16_t hdr_len = sizeof(struct ip6_hdr);
   if (sizeof(struct ip6_hdr) > data_len) {
      throw "Parser detected malformed packet";
   }

   pkt->ip_version = IP::v6;
   pkt->ip_tos = (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20;
   pkt->ip_proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
   pkt->ip_ttl = ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
   pkt->ip_flags = 0;
   pkt->ip_payload_len = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
   pkt->ip_len = pkt->ip_payload_len + 40;
   memcpy(pkt->src_ip.v6, (const char *) &ip6->ip6_src, 16);
   memcpy(pkt->dst_ip.v6, (const char *) &ip6->ip6_dst, 16);

   DEBUG_CODE(char buffer[INET6_ADDRSTRLEN]);
   DEBUG_MSG("IPv6 header:\n");
   DEBUG_MSG("\tVersion:\t%u\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xf0000000) >> 28);
   DEBUG_MSG("\tClass:\t\t%u\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20);
   DEBUG_MSG("\tFlow:\t\t%#x\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000fffff));
   DEBUG_MSG("\tLength:\t\t%u\n",      ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
   DEBUG_MSG("\tProtocol:\t%u\n",      ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
   DEBUG_MSG("\tHop limit:\t%u\n",     ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);

   DEBUG_CODE(inet_ntop(AF_INET6, (const void *) &ip6->ip6_src, buffer, INET6_ADDRSTRLEN));
   DEBUG_MSG("\tSrc addr:\t%s\n",      buffer);
   DEBUG_CODE(inet_ntop(AF_INET6, (const void *) &ip6->ip6_dst, buffer, INET6_ADDRSTRLEN));
   DEBUG_MSG("\tDest addr:\t%s\n",     buffer);

   if (pkt->ip_proto != IPPROTO_TCP && pkt->ip_proto != IPPROTO_UDP) {
      hdr_len += skip_ipv6_ext_hdrs(data_ptr + hdr_len, data_len - hdr_len, pkt);
   }

   return hdr_len;
}

/**
 * \brief Parse specific fields from TCP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_tcp_hdr(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct tcphdr *tcp = (struct tcphdr *) data_ptr;
   if (sizeof(struct tcphdr) > data_len) {
      throw "Parser detected malformed packet";
   }

   pkt->src_port = ntohs(tcp->source);
   pkt->dst_port = ntohs(tcp->dest);
   pkt->tcp_flags = (uint8_t) *(data_ptr + 13) & 0xFF;
   pkt->tcp_window = ntohs(tcp->window);

   DEBUG_MSG("TCP header:\n");
   DEBUG_MSG("\tSrc port:\t%u\n",   ntohs(tcp->source));
   DEBUG_MSG("\tDest port:\t%u\n",  ntohs(tcp->dest));
   DEBUG_MSG("\tSEQ:\t\t%#x\n",     ntohl(tcp->seq));
   DEBUG_MSG("\tACK SEQ:\t%#x\n",   ntohl(tcp->ack_seq));
   DEBUG_MSG("\tData offset:\t%u\n",tcp->doff);
   DEBUG_MSG("\tFlags:\t\t%s%s%s%s%s%s\n", (tcp->fin ? "FIN " : ""), (tcp->syn ? "SYN " : ""),
                                           (tcp->rst ? "RST " : ""), (tcp->psh ? "PSH " : ""),
                                           (tcp->ack ? "ACK " : ""), (tcp->urg ? "URG"  : ""));
   DEBUG_MSG("\tWindow:\t\t%u\n",   ntohs(tcp->window));
   DEBUG_MSG("\tChecksum:\t%#06x\n",ntohs(tcp->check));
   DEBUG_MSG("\tUrg ptr:\t%#x\n",   ntohs(tcp->urg_ptr));
   DEBUG_MSG("\tReserved1:\t%#x\n", tcp->res1);
   DEBUG_MSG("\tReserved2:\t%#x\n", tcp->res2);

   int hdr_len = tcp->doff << 2;
   int hdr_opt_len = hdr_len - sizeof(struct tcphdr);
   int i = 0;
   DEBUG_MSG("\tTCP_OPTIONS (%uB):\n", hdr_opt_len);
   if (hdr_len > data_len) {
      throw "Parser detected malformed packet";
   }
   while (i < hdr_opt_len) {
      uint8_t *opt_ptr = (uint8_t *) data_ptr + sizeof(struct tcphdr) + i;
      uint8_t opt_kind = *opt_ptr;
      if (i + 1 >= hdr_opt_len) {
         if (opt_kind <= 1) {
            return hdr_len;
         }
         throw "Parser detected malformed packet";
      }
      uint8_t opt_len = (opt_kind <= 1 ? 1 : *(opt_ptr + 1));
      DEBUG_MSG("\t\t%u: len=%u\n", opt_kind, opt_len);

      pkt->tcp_options |= ((uint64_t) 1 << opt_kind);
      if (opt_kind == 0x00) {
         break;
      } else if (opt_kind == 0x02) {
         // Parse Maximum Segment Size (MSS)
         pkt->tcp_mss = ntohl(*(uint32_t *) (opt_ptr + 2));
      }
      if (opt_len == 0) {
         // Prevent infinity loop
         throw "Parser detected malformed packet";
      }
      i += opt_len;
   }

   return hdr_len;
}

/**
 * \brief Parse specific fields from UDP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_udp_hdr(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct udphdr *udp = (struct udphdr *) data_ptr;
   if (sizeof(struct udphdr) > data_len) {
      throw "Parser detected malformed packet";
   }

   pkt->src_port = ntohs(udp->source);
   pkt->dst_port = ntohs(udp->dest);

   DEBUG_MSG("UDP header:\n");
   DEBUG_MSG("\tSrc port:\t%u\n",   ntohs(udp->source));
   DEBUG_MSG("\tDest port:\t%u\n",  ntohs(udp->dest));
   DEBUG_MSG("\tLength:\t\t%u\n",   ntohs(udp->len));
   DEBUG_MSG("\tChecksum:\t%#06x\n",ntohs(udp->check));

   return 8;
}

/**
 * \brief Parse specific fields from ICMP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_icmp_hdr(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct icmphdr *icmp = (struct icmphdr *) data_ptr;
   if (sizeof(struct icmphdr) > data_len) {
      throw "Parser detected malformed packet";
   }
   pkt->dst_port = icmp->type * 256 + icmp->code;

   DEBUG_MSG("ICMP header:\n");
   DEBUG_MSG("\tType:\t\t%u\n",     icmp->type);
   DEBUG_MSG("\tCode:\t\t%u\n",     icmp->code);
   DEBUG_MSG("\tChecksum:\t%#06x\n",ntohs(icmp->checksum));
   DEBUG_MSG("\tRest:\t\t%#06x\n",  ntohl(*(uint32_t *) &icmp->un));

   return 0;
}

/**
 * \brief Parse specific fields from ICMPv6 header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_icmpv6_hdr(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) data_ptr;
   if (sizeof(struct icmp6_hdr) > data_len) {
      throw "Parser detected malformed packet";
   }
   pkt->dst_port = icmp6->icmp6_type * 256 + icmp6->icmp6_code;

   DEBUG_MSG("ICMPv6 header:\n");
   DEBUG_MSG("\tType:\t\t%u\n",     icmp6->icmp6_type);
   DEBUG_MSG("\tCode:\t\t%u\n",     icmp6->icmp6_code);
   DEBUG_MSG("\tChecksum:\t%#x\n",  ntohs(icmp6->icmp6_cksum));
   DEBUG_MSG("\tBody:\t\t%#x\n",    ntohs(*(uint32_t *) &icmp6->icmp6_dataun));

   return 0;
}

/**
 * \brief Skip MPLS stack.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \return Size of headers in bytes.
 */
uint16_t process_mpls_stack(const u_char *data_ptr, uint16_t data_len)
{
   uint32_t *mpls;
   uint16_t length = 0;

   do {
      mpls = (uint32_t *) (data_ptr + length);
      length += sizeof(uint32_t);
      if (0 > data_len - length) {
         throw "Parser detected malformed packet";
      }

      DEBUG_MSG("MPLS:\n");
      DEBUG_MSG("\tLabel:\t%u\n",   ntohl(*mpls) >> 12);
      DEBUG_MSG("\tTC:\t%u\n",      (ntohl(*mpls) & 0xE00) >> 9);
      DEBUG_MSG("\tBOS:\t%u\n",     (ntohl(*mpls) & 0x100) >> 8);
      DEBUG_MSG("\tTTL:\t%u\n",     ntohl(*mpls) & 0xFF);

    } while (!(ntohl(*mpls) & 0x100));

   return length;
}

/**
 * \brief Skip MPLS stack and parse the following header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of parsed data in bytes.
 */
uint16_t process_mpls(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   Packet tmp;
   uint16_t length = process_mpls_stack(data_ptr, data_len);
   uint8_t next_hdr = (*(data_ptr + length) & 0xF0) >> 4;

   if (next_hdr == IP::v4) {
      length += parse_ipv4_hdr(data_ptr + length, data_len - length, pkt);
   } else if (next_hdr == IP::v6) {
      length += parse_ipv6_hdr(data_ptr + length, data_len - length, pkt);
   } else if (next_hdr == 0) {
      /* Process EoMPLS */
      length += 4; /* Skip Pseudo Wire Ethernet control word. */
      length = parse_eth_hdr(data_ptr + length, data_len - length, &tmp);
      if (tmp.ethertype == ETH_P_IP) {
         length += parse_ipv4_hdr(data_ptr + length, data_len - length, pkt);
      } else if (tmp.ethertype == ETH_P_IPV6) {
         length += parse_ipv6_hdr(data_ptr + length, data_len - length, pkt);
      }
   }

   return length;
}

/**
 * \brief Parse PPPOE header and the following IP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [in] data_len Length of packet data in `data_ptr`.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of parsed data in bytes.
 */
inline uint16_t process_pppoe(const u_char *data_ptr, uint16_t data_len, Packet *pkt)
{
   struct pppoe_hdr *pppoe = (struct pppoe_hdr *) data_ptr;
   if (sizeof(struct pppoe_hdr) + 2 > data_len) {
      throw "Parser detected malformed packet";
   }
   uint16_t next_hdr = ntohs(*(uint16_t *) (data_ptr + sizeof(struct pppoe_hdr)));
   uint16_t length = sizeof(struct pppoe_hdr) + 2;

   DEBUG_MSG("PPPoE header:\n");
   DEBUG_MSG("\tVer:\t%u\n",     pppoe->version);
   DEBUG_MSG("\tType:\t%u\n",    pppoe->type);
   DEBUG_MSG("\tCode:\t%u\n",    pppoe->code);
   DEBUG_MSG("\tSID:\t%u\n",     ntohs(pppoe->sid));
   DEBUG_MSG("\tLength:\t%u\n",  ntohs(pppoe->length));
   DEBUG_MSG("PPP header:\n");
   DEBUG_MSG("\tProtocol:\t%#04x\n", next_hdr);
   if (pppoe->code != 0) {
      return length;
   }

   if (next_hdr == 0x0021) {
      length += parse_ipv4_hdr(data_ptr + length, data_len - length, pkt);
   } else if (next_hdr == 0x0057) {
      length += parse_ipv6_hdr(data_ptr + length, data_len - length, pkt);
   }

   return length;
}

void parse_packet(parser_opt_t *opt, struct timeval ts, const uint8_t *data, uint16_t len, uint16_t caplen)
{
   if (opt->pblock->cnt >= opt->pblock->size) {
      return;
   }
   Packet *pkt = &opt->pblock->pkts[opt->pblock->cnt];
   uint16_t data_offset = 0;

   DEBUG_MSG("---------- packet parser  #%u -------------\n", ++s_total_pkts);
   DEBUG_CODE(
      char timestamp[32];
      time_t time = ts.tv_sec;
      strftime(timestamp, sizeof(timestamp), "%FT%T", localtime(&time));
   );
   DEBUG_MSG("Time:\t\t\t%s.%06lu\n",     timestamp, ts.tv_usec);
   DEBUG_MSG("Packet length:\t\tcaplen=%uB len=%uB\n\n", caplen, len);

   pkt->packet_len_wire = len;
   pkt->ts = ts;
   pkt->src_port = 0;
   pkt->dst_port = 0;
   pkt->ip_proto = 0;
   pkt->ip_ttl = 0;
   pkt->ip_flags = 0;
   pkt->ip_version = 0;
   pkt->ip_payload_len = 0;
   pkt->tcp_flags = 0;
   pkt->tcp_window = 0;
   pkt->tcp_options = 0;
   pkt->tcp_mss = 0;

   uint32_t l3_hdr_offset = 0;
   uint32_t l4_hdr_offset = 0;
   try {
   #ifdef WITH_PCAP
      if (opt->datalink == DLT_EN10MB) {
         data_offset = parse_eth_hdr(data, caplen, pkt);
      } else if (opt->datalink == DLT_LINUX_SLL) {
            data_offset = parse_sll(data, caplen, pkt);
   # ifdef DLT_LINUX_SLL2
      } else if (opt->datalink == DLT_LINUX_SLL2) {
            data_offset = parse_sll2(data, caplen, pkt);
   # endif /* DLT_LINUX_SLL2 */
      } else if (opt->datalink == DLT_RAW) {
            if ((data[0] & 0xF0) == 0x40) {
               pkt->ethertype = ETH_P_IP;
            } else if ((data[0] & 0xF0) == 0x60) {
               pkt->ethertype = ETH_P_IPV6;
            }
      }
   #else
      data_offset = parse_eth_hdr(data, caplen, pkt);
   #endif /* WITH_PCAP */

      if (pkt->ethertype == ETH_P_TRILL) {
         data_offset += parse_trill(data + data_offset, caplen - data_offset, pkt);
         data_offset += parse_eth_hdr(data + data_offset, caplen - data_offset, pkt);
      }
      l3_hdr_offset = data_offset;
      if (pkt->ethertype == ETH_P_IP) {
         data_offset += parse_ipv4_hdr(data + data_offset, caplen - data_offset, pkt);
      } else if (pkt->ethertype == ETH_P_IPV6) {
         data_offset += parse_ipv6_hdr(data + data_offset, caplen - data_offset, pkt);
      } else if (pkt->ethertype == ETH_P_MPLS_UC || pkt->ethertype == ETH_P_MPLS_MC) {
         data_offset += process_mpls(data + data_offset, caplen - data_offset, pkt);
      } else if (pkt->ethertype == ETH_P_PPP_SES) {
         data_offset += process_pppoe(data + data_offset, caplen - data_offset, pkt);
      } else if (!opt->parse_all) {
         DEBUG_MSG("Unknown ethertype %x\n", pkt->ethertype);
         return;
      }

      l4_hdr_offset = data_offset;
      if (pkt->ip_proto == IPPROTO_TCP) {
         data_offset += parse_tcp_hdr(data + data_offset, caplen - data_offset, pkt);
      } else if (pkt->ip_proto == IPPROTO_UDP) {
         data_offset += parse_udp_hdr(data + data_offset, caplen - data_offset, pkt);
      } else if (pkt->ip_proto == IPPROTO_ICMP) {
         data_offset += parse_icmp_hdr(data + data_offset, caplen - data_offset, pkt);
      } else if (pkt->ip_proto == IPPROTO_ICMPV6) {
         data_offset += parse_icmpv6_hdr(data + data_offset, caplen - data_offset, pkt);
      }
   } catch (const char *err) {
      DEBUG_MSG("%s\n", err);
      return;
   }

   uint16_t pkt_len = caplen;
   pkt->packet = data;
   pkt->packet_len = caplen;

   if (l4_hdr_offset != l3_hdr_offset) {
      if (l4_hdr_offset + pkt->ip_payload_len < 64) {
         // Packet contains 0x00 padding bytes, do not include them in payload
         pkt_len = l4_hdr_offset + pkt->ip_payload_len;
      }
      pkt->payload_len_wire = pkt->ip_payload_len - (data_offset - l4_hdr_offset);
   } else {
      pkt->payload_len_wire = pkt_len - data_offset;
   }

   pkt->payload_len = pkt->payload_len_wire;
   if (pkt->payload_len + data_offset > pkt_len) {
      // Set correct size when payload length is bigger than captured payload length
      pkt->payload_len = pkt_len - data_offset;
   }
   pkt->payload = pkt->packet + data_offset;

   DEBUG_MSG("Payload length:\t%u\n", pkt->payload_len);
   DEBUG_MSG("Packet parser exits: packet parsed\n");
   opt->packet_valid = true;
   opt->pblock->cnt++;
   opt->pblock->bytes += len;
}

}
