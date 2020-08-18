/**
 * \file pcapreader.cpp
 * \brief Pcap reader based on libpcap
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2014-2015 CESNET
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
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#ifndef HAVE_NDP
#include <pcap/pcap.h>
#endif /* HAVE_NDP */

#include "pcapreader.h"

using namespace std;

// Read timeout in miliseconds for pcap_open_live function.
#define READ_TIMEOUT 1000

// Interval between pcap handle stats print in seconds.
#define STATS_PRINT_INTERVAL  5

//#define DEBUG_PARSER

#ifdef DEBUG_PARSER
// Print debug message if debugging is allowed.
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
// Process code if debugging is allowed.
#define DEBUG_CODE(code) code
#else
#define DEBUG_MSG(format, ...)
#define DEBUG_CODE(code)
#endif

#ifdef DEBUG_PARSER
static uint32_t s_total_pkts = 0;
#endif /* DEBUG_PARSER */

/**
 * \brief Distinguish between valid (parsed) and non-valid packet.
 */
bool packet_valid = false;

/**
 * \brief Parse every packet.
 */
bool parse_all = false;

/**
 * \brief Parse specific fields from ETHERNET frame header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_eth_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct ethhdr *eth = (struct ethhdr *) data_ptr;
   uint16_t hdr_len = 14, ethertype = ntohs(eth->h_proto);

   DEBUG_MSG("Ethernet header:\n");
   DEBUG_MSG("\tDest mac:\t%s\n",         ether_ntoa((struct ether_addr *) eth->h_dest));
   DEBUG_MSG("\tSrc mac:\t%s\n",          ether_ntoa((struct ether_addr *) eth->h_source));
   DEBUG_MSG("\tEthertype:\t%#06x\n",     ethertype);

   memcpy(pkt->dst_mac, eth->h_dest, 6);
   memcpy(pkt->src_mac, eth->h_source, 6);

   if (ethertype == ETH_P_8021AD) {
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

struct __attribute__((packed)) trill_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
   uint8_t op_len1:3;
   uint8_t m:1;
   uint8_t res:2;
   uint8_t version:2;
   uint8_t hop_cnt:6;
   uint8_t op_len2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
   uint8_t version:2;
   uint8_t res:2;
   uint8_t m:1;
   uint8_t op_len1:3;
   uint8_t op_len2:2;
   uint8_t hop_cnt:6;
#endif
   uint16_t egress_nick;
   uint16_t ingress_nick;
};


/**
 * \brief Parse specific fields from TRILL.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_trill(const u_char *data_ptr, Packet *pkt)
{
   struct trill_hdr *trill = (struct trill_hdr *) data_ptr;
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
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_ipv4_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct iphdr *ip = (struct iphdr *) data_ptr;

   pkt->ip_version = 4;
   pkt->ip_proto = ip->protocol;
   pkt->ip_tos = ip->tos;
   pkt->ip_length = ntohs(ip->tot_len);
   pkt->ip_ttl = ip->ttl;
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
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Length of headers in bytes.
 */
uint16_t skip_ipv6_ext_hdrs(const u_char *data_ptr, Packet *pkt)
{
   struct ip6_ext *ext = (struct ip6_ext *) data_ptr;
   uint8_t next_hdr = pkt->ip_proto;
   uint16_t hdrs_len = 0;

   /* Skip extension headers... */
   while (1) {
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

   return hdrs_len;
}

/**
 * \brief Parse specific fields from IPv6 header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_ipv6_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct ip6_hdr *ip6 = (struct ip6_hdr *) data_ptr;
   uint16_t hdr_len = 40;

   pkt->ip_version = 6;
   pkt->ip_tos = (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20;
   pkt->ip_proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
   pkt->ip_ttl = ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
   pkt->ip_length = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) + 40;
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
      hdr_len += skip_ipv6_ext_hdrs(data_ptr + hdr_len, pkt);
   }

   return hdr_len;
}

/**
 * \brief Parse specific fields from TCP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_tcp_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct tcphdr *tcp = (struct tcphdr *) data_ptr;

   pkt->field_indicator |= (PCKT_TCP | PCKT_PAYLOAD);
   pkt->src_port = ntohs(tcp->source);
   pkt->dst_port = ntohs(tcp->dest);
   pkt->tcp_control_bits = (uint8_t) *(data_ptr + 13) & 0xFF;

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

   return (tcp->doff << 2);
}

/**
 * \brief Parse specific fields from UDP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_udp_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct udphdr *udp = (struct udphdr *) data_ptr;

   pkt->field_indicator |= (PCKT_UDP | PCKT_PAYLOAD);
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
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_icmp_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct icmphdr *icmp = (struct icmphdr *) data_ptr;
   pkt->dst_port = icmp->type * 256 + icmp->code;
   pkt->field_indicator |= PCKT_ICMP;

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
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_icmpv6_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) data_ptr;
   pkt->dst_port = icmp6->icmp6_type * 256 + icmp6->icmp6_code;
   pkt->field_indicator |= PCKT_ICMP;

   DEBUG_MSG("ICMPv6 header:\n");
   DEBUG_MSG("\tType:\t\t%u\n",     icmp6->icmp6_type);
   DEBUG_MSG("\tCode:\t\t%u\n",     icmp6->icmp6_code);
   DEBUG_MSG("\tChecksum:\t%#x\n",  ntohs(icmp6->icmp6_cksum));
   DEBUG_MSG("\tBody:\t\t%#x\n",    ntohs(*(uint32_t *) &icmp6->icmp6_dataun));

   return 0;
}

uint16_t process_mpls_stack(const u_char *data_ptr)
{
   uint32_t *mpls;
   uint16_t length = 0;

   do {
      mpls = (uint32_t *) (data_ptr + length);
      length += sizeof(uint32_t);

      DEBUG_MSG("MPLS:\n");
      DEBUG_MSG("\tLabel:\t%u\n",   ntohl(*mpls) >> 12);
      DEBUG_MSG("\tTC:\t%u\n",      (ntohl(*mpls) & 0xE00) >> 9);
      DEBUG_MSG("\tBOS:\t%u\n",     (ntohl(*mpls) & 0x100) >> 8);
      DEBUG_MSG("\tTTL:\t%u\n",     ntohl(*mpls) & 0xFF);

    } while (!(ntohl(*mpls) & 0x100));

   return length;
}

uint16_t process_mpls(const u_char *data_ptr, Packet *pkt)
{
   Packet tmp;
   uint16_t length = process_mpls_stack(data_ptr);
   uint8_t next_hdr = (*(data_ptr + length) & 0xF0) >> 4;

   if (next_hdr == 4) {
      length += parse_ipv4_hdr(data_ptr + length, pkt);
   } else if (next_hdr == 6) {
      length += parse_ipv6_hdr(data_ptr + length, pkt);
   } else if (next_hdr == 0) {
      /* Process EoMPLS */
      length += 4; /* Skip Pseudo Wire Ethernet control word. */
      length = parse_eth_hdr(data_ptr + length, &tmp);
      if (tmp.ethertype == ETH_P_IP) {
         length += parse_ipv4_hdr(data_ptr + length, pkt);
      } else if (tmp.ethertype == ETH_P_IPV6) {
         length += parse_ipv6_hdr(data_ptr + length, pkt);
      }
   }

   return length;
}

struct __attribute__((packed)) pppoe_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
   uint8_t type:4;
   uint8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
   uint8_t version:4;
   uint8_t type:4;
#endif
   uint8_t code;
   uint16_t sid;
   uint16_t length;
};

inline uint16_t process_pppoe(const u_char *data_ptr, Packet *pkt)
{
   struct pppoe_hdr *pppoe = (struct pppoe_hdr *) data_ptr;
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
      length += parse_ipv4_hdr(data_ptr + length, pkt);
   } else if (next_hdr == 0x0057) {
      length += parse_ipv6_hdr(data_ptr + length, pkt);
   }

   return length;
}


void parse_packet(Packet *pkt, struct timeval ts, const uint8_t *data, uint16_t len, uint16_t caplen)
{
   uint16_t data_offset = 0;

   DEBUG_MSG("---------- packet parser  #%u -------------\n", ++s_total_pkts);
   DEBUG_CODE(
      char timestamp[32];
      time_t time = ts.tv_sec;
      strftime(timestamp, sizeof(timestamp), "%FT%T", localtime(&time));
   );
   DEBUG_MSG("Time:\t\t\t%s.%06lu\n",     timestamp, ts.tv_usec);
   DEBUG_MSG("Packet length:\t\tcaplen=%uB len=%uB\n\n", caplen, len);

   pkt->timestamp = ts;
   pkt->field_indicator = 0;
   pkt->src_port = 0;
   pkt->dst_port = 0;
   pkt->ip_proto = 0;
   pkt->ip_version = 0;
   pkt->tcp_control_bits = 0;

   data_offset = parse_eth_hdr(data, pkt);
   if (pkt->ethertype == ETH_P_TRILL) {
      data_offset += parse_trill(data + data_offset, pkt);
      data_offset += parse_eth_hdr(data + data_offset, pkt);
   }
   if (pkt->ethertype == ETH_P_IP) {
      data_offset += parse_ipv4_hdr(data + data_offset, pkt);
   } else if (pkt->ethertype == ETH_P_IPV6) {
      data_offset += parse_ipv6_hdr(data + data_offset, pkt);
   } else if (pkt->ethertype == ETH_P_MPLS_UC || pkt->ethertype == ETH_P_MPLS_MC) {
      data_offset += process_mpls(data + data_offset, pkt);
   } else if (pkt->ethertype == ETH_P_PPP_SES) {
      data_offset += process_pppoe(data + data_offset, pkt);
   } else if (!parse_all) {
      DEBUG_MSG("Unknown ethertype %x\n", pkt->ethertype);
      return;
   }

   if (pkt->ip_proto == IPPROTO_TCP) {
      data_offset += parse_tcp_hdr(data + data_offset, pkt);
   } else if (pkt->ip_proto == IPPROTO_UDP) {
      data_offset += parse_udp_hdr(data + data_offset, pkt);
   } else if (pkt->ip_proto == IPPROTO_ICMP) {
      data_offset += parse_icmp_hdr(data + data_offset, pkt);
   } else if (pkt->ip_proto == IPPROTO_ICMPV6) {
      data_offset += parse_icmpv6_hdr(data + data_offset, pkt);
   }

   uint32_t pkt_len = caplen;
   if (pkt_len > MAXPCKTSIZE) {
      pkt_len = MAXPCKTSIZE;
      DEBUG_MSG("Packet size too long, truncating to %u\n", pkt_len);
   }
   memcpy(pkt->packet, data, pkt_len);
   pkt->packet[pkt_len] = 0;
   pkt->total_length = pkt_len;

   pkt->payload_length = pkt_len - data_offset;
   pkt->payload = pkt->packet + data_offset;

   DEBUG_MSG("Payload length:\t%u\n", pkt->payload_length);
   DEBUG_MSG("Packet parser exits: packet parsed\n");
   packet_valid = true;
}

#ifndef HAVE_NDP

/**
 * \brief Parsing callback function for pcap_dispatch() call. Parse packets up to transport layer.
 * \param [in,out] arg Serves for passing pointer to Packet structure into callback function.
 * \param [in] h Contains timestamp and packet size.
 * \param [in] data Pointer to the captured packet data.
 */
void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data)
{
   parse_packet((Packet *) arg, h->ts, data, h->len, h->caplen);
}

static void print_libpcap_stats(pcap_t *handle) {
    struct pcap_stat cap_stats;

    memset(&cap_stats, 0x00, sizeof(struct pcap_stat));
    if (pcap_stats(handle, &cap_stats) == 0) {
       fprintf(stderr,"Libpcap Stats: Received %u, Mem Dropped %u, IF Dropped %u\n",
            cap_stats.ps_recv, cap_stats.ps_drop, cap_stats.ps_ifdrop);
    } else {
        /* stats failed to be retrieved */
       fprintf(stderr,"Libpcap Stats: -= unavailable =-\n");
    }
}

/**
 * \brief Constructor.
 */
PcapReader::PcapReader() : handle(NULL), print_pcap_stats(false), netmask(PCAP_NETMASK_UNKNOWN)
{
}

/**
 * \brief Constructor.
 * \param [in] options Module options.
 */
PcapReader::PcapReader(const options_t &options) : handle(NULL), netmask(PCAP_NETMASK_UNKNOWN)
{
   print_pcap_stats = options.print_pcap_stats;
   last_ts.tv_sec = 0;
   last_ts.tv_usec = 0;
}

PcapReader::~PcapReader()
{
   this->close();
}

/**
 * \brief Open pcap file for reading.
 * \param [in] file Input file name.
 * \param [in] parse_every_pkt Try to parse every captured packet.
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int PcapReader::open_file(const string &file, bool parse_every_pkt)
{
   if (handle != NULL) {
      error_msg = "Interface or pcap file is already opened.";
      return 1;
   }

   char error_buffer[PCAP_ERRBUF_SIZE];
   handle = pcap_open_offline(file.c_str(), error_buffer);
   if (handle == NULL) {
      error_msg = error_buffer;
      return 2;
   }

   if (print_pcap_stats) {
      printf("PcapReader: warning: printing pcap stats is only supported in live capture\n");
   }

   live_capture = false;
   parse_all = parse_every_pkt;
   error_msg = "";
   return 0;
}

/**
 * \brief Initialize network interface for reading.
 * \param [in] interface Interface name.
 * \param [in] snaplen Snapshot length to be set on pcap handle.
 * \param [in] parse_every_pkt Try to parse every captured packet.
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int PcapReader::init_interface(const string &interface, int snaplen, bool parse_every_pkt)
{
   if (handle != NULL) {
      error_msg = "Interface or pcap file is already opened.";
      return 1;
   }

   char errbuf[PCAP_ERRBUF_SIZE];
   errbuf[0] = 0;

   handle = pcap_open_live(interface.c_str(), snaplen, 1, READ_TIMEOUT, errbuf);
   if (handle == NULL) {
      error_msg = errbuf;
      return 2;
   }
   if (errbuf[0] != 0) {
      fprintf(stderr, "%s\n", errbuf); // Print warning.
   }

   if (pcap_datalink(handle) != DLT_EN10MB) {
      error_msg = "Unsupported data link type.";
      close();
      return 3;
   }

   bpf_u_int32 net;
   if (pcap_lookupnet(interface.c_str(), &net, &netmask, errbuf) != 0) {
      netmask = PCAP_NETMASK_UNKNOWN;
   }

   if (print_pcap_stats) {
      /* Print stats header. */
      printf("# recv   - number of packets received\n");
      printf("# drop   - number  of  packets dropped because there was no room in the operating system's buffer when they arrived, because packets weren't being read fast enough\n");
      printf("# ifdrop - number of packets dropped by the network interface or its driver\n\n");
      printf("recv\tdrop\tifdrop\n");
   }

   live_capture = true;
   parse_all = parse_every_pkt;
   error_msg = "";
   return 0;
}

/**
 * \brief Install BPF filter to pcap handle.
 * \param [in] filter_str String containing program.
 * \return 0 on success, non 0 on failure.
 */
int PcapReader::set_filter(const string &filter_str)
{
   if (handle == NULL) {
      error_msg = "No live capture or file opened.";
      return 1;
   }

   struct bpf_program filter;
   if (pcap_compile(handle, &filter, filter_str.c_str(), 0, netmask) == -1) {
      error_msg = "Couldn't parse filter " + string(filter_str) + ": " + string(pcap_geterr(handle));
      return 1;
   }
   if (pcap_setfilter(handle, &filter) == -1) {
      pcap_freecode(&filter);
      error_msg = "Couldn't install filter " + string(filter_str) + ": " + string(pcap_geterr(handle));
      return 1;
   }

   pcap_freecode(&filter);
   return 0;
}

void PcapReader::printStats()
{
   print_libpcap_stats(handle);
}
/**
 * \brief Close opened file or interface.
 */
void PcapReader::close()
{
   if (handle != NULL) {
      pcap_close(handle);
      handle = NULL;
   }
}

void PcapReader::print_stats()
{
   /* Only live capture stats are supported. */
   if (live_capture) {
      struct timeval tmp;

      gettimeofday(&tmp, NULL);
      if (tmp.tv_sec - last_ts.tv_sec >= STATS_PRINT_INTERVAL) {
         struct pcap_stat stats;
         if (pcap_stats(handle, &stats) == -1) {
            printf("PcapReader: error: %s\n", pcap_geterr(handle));
            print_pcap_stats = false; /* Turn off printing stats. */
            return;
         }
         printf("%d\t%d\t%d\n", stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);

         last_ts = tmp;
      }
   }
}

int PcapReader::get_pkt(Packet &packet)
{
   if (handle == NULL) {
      error_msg = "No live capture or file opened.";
      return -3;
   }

   int ret;
   packet_valid = false;

   if (print_pcap_stats) {
      //print_stats();
   }

   // Get pkt from network interface or file.
   ret = pcap_dispatch(handle, 1, packet_handler, (u_char *) (&packet));
   if (ret == 0) {
      // Read timeout occured or no more packets in file...
      return (live_capture ? 3 : 0);
   }

   if (ret == 1 && packet_valid) {
      // Packet is valid and ready to process by flow_cache.
      return 2;
   }
   if (ret < 0) {
      // Error occured.
      error_msg = pcap_geterr(handle);
   }
   return ret;
 }

#else /* HAVE_NDP */
void packet_ndp_handler(Packet *pkt, const struct ndp_packet *ndp_packet, const struct ndp_header *ndp_header)
{
   struct timeval ts;
   ts.tv_sec = ndp_header->timestamp_sec;
   ts.tv_usec = ndp_header->timestamp_nsec / 1000;

   parse_packet(pkt, ts, ndp_packet->data, ndp_packet->data_length, ndp_packet->data_length);
}

/**
 * \brief Constructor.
 */
NdpPacketReader::NdpPacketReader() : print_pcap_stats(false)
{
}

/**
 * \brief Constructor.
 * \param [in] options Module options.
 */
NdpPacketReader::NdpPacketReader(const options_t &options)
{
   print_pcap_stats = options.print_pcap_stats;
}

/**
 * \brief Destructor.
 */
NdpPacketReader::~NdpPacketReader()
{
   this->close();
}

/**
 * \brief Open pcap file for reading.
 * \param [in] file Input file name.
 * \param [in] parse_every_pkt Try to parse every captured packet.
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int NdpPacketReader::open_file(const string &file, bool parse_every_pkt)
{
   error_msg = "Pcap Not suported in this mode";
   return 1;
}

/**
 * \brief Initialize network interface for reading.
 * \param [in] interface Interface name.
 * \param [in] snaplen Snapshot length to be set on pcap handle.
 * \param [in] parse_every_pkt Try to parse every captured packet.
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int NdpPacketReader::init_interface(const string &interface, int snaplen, bool parse_every_pkt)
{
   int res;
   res = ndpReader.init_interface(interface);
   error_msg = ndpReader.error_msg;

   live_capture = true;
   parse_all = parse_every_pkt;
   return res;
}

/**
 * \brief Install BPF filter to pcap handle.
 * \param [in] filter_str String containing program.
 * \return 0 on success, non 0 on failure.
 */
int NdpPacketReader::set_filter(const string &filter_str)
{
   error_msg = "Filters not supported";
   return 1;
}

void NdpPacketReader::printStats()
{
   ndpReader.print_stats();
}
/**
 * \brief Close opened file or interface.
 */
void NdpPacketReader::close()
{
   ndpReader.close();
}

int NdpPacketReader::get_pkt(Packet &packet)
{
   int ret;
   packet_valid = false;

   if (print_pcap_stats) {
      //print_stats();
   }

   struct ndp_packet *ndp_packet;
   struct ndp_header *ndp_header;

   ret = ndpReader.get_pkt(&ndp_packet, &ndp_header);
   if (ret == 0) {
	   return (live_capture ? 3 : 0);
   }
   packet_ndp_handler(&packet, ndp_packet, ndp_header);

   if (ret == 1 && packet_valid) {
      // Packet is valid and ready to process by flow_cache.
      return 2;
   }
   if (ret < 0) {
      // Error occured.
      error_msg = ndpReader.error_msg;
   }
   return ret;
}
#endif /* HAVE_NDP */
