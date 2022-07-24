/**
 * \file raw.cpp
 * \brief Packet reader using raw sockets.
 *    More info at https://www.kernel.org/doc/html/latest/networking/packet_mmap.html
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
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iomanip>

#include <unistd.h>
#include <poll.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "raw.hpp"
#include "parser.hpp"

namespace ipxp {

#ifndef TPACKET3_HDRLEN
#error "raw plugin is supported with TPACKET3 only"
#endif

// Read only 1 packet into packet block
constexpr size_t RAW_PACKET_BLOCK_SIZE = 1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("raw", [](){return new RawReader();});
   register_plugin(&rec);
}

RawReader::RawReader() : m_sock(-1), m_fanout(0), m_rd(nullptr), m_pfd({0}), m_buffer(nullptr), m_buffer_size(0),
   m_block_idx(0), m_blocksize(0), m_framesize(0), m_blocknum(0), m_last_ppd(nullptr), m_pbd(nullptr), m_pkts_left(0)
{
}

RawReader::~RawReader()
{
   close();
}

void RawReader::init(const char *params)
{
   RawOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   if (parser.m_list) {
      print_available_ifcs();
      throw PluginExit();
   }

   m_fanout = parser.m_fanout;
   if (parser.m_ifc.empty()) {
      throw PluginError("specify network interface");
   }

   long pagesize = sysconf(_SC_PAGESIZE);
   if (pagesize == -1) {
      throw PluginError("get page size failed");
   }

   m_blocksize = pagesize * parser.m_pkt_cnt;
   m_framesize = 2048;
   m_blocknum = parser.m_block_cnt;

   if (static_cast<long>(m_framesize) > pagesize) {
      m_framesize = pagesize;
   }

   open_ifc(parser.m_ifc);
}

void RawReader::close()
{
   if (m_buffer != nullptr) {
      munmap(m_buffer, m_buffer_size);
      m_buffer = nullptr;
   }
   if (m_rd != nullptr) {
      free(m_rd);
      m_rd = nullptr;
   }
   if (m_sock >= 0) {
      ::close(m_sock);
      m_sock = -1;
   }
}

void RawReader::open_ifc(const std::string &ifc)
{
   int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   if (sock == -1) {
      throw PluginError(std::string("could not create AF_PACKET socket: ") + strerror(errno));
   }

   int version = TPACKET_V3;
   int ssopt_pkt_version = setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
   if (ssopt_pkt_version == -1) {
      ::close(sock);
      throw PluginError(std::string("unable to set packet to v3: ") + strerror(errno));
   }

   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));
   if (ifc.size() > sizeof(ifr.ifr_name) - 1) {
      ::close(sock);
      throw PluginError("interface name is too long");
   }
   strncpy(ifr.ifr_name, ifc.c_str(), sizeof(ifr.ifr_name) - 1);

   if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
      ::close(sock);
      throw PluginError(std::string("unable to get ifc number: ioctl failed: ") + strerror(errno));
   }

   int ifc_num = ifr.ifr_ifindex;

   struct packet_mreq sock_params;
   memset(&sock_params, 0, sizeof(sock_params));
   sock_params.mr_type = PACKET_MR_PROMISC;
   sock_params.mr_ifindex = ifc_num;

   int set_promisc = setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, static_cast<void*>(&sock_params), sizeof(sock_params));
   if (set_promisc == -1) {
      ::close(sock);
      throw PluginError(std::string("unable to set ifc to promisc mode: ") + strerror(errno));
   }

   struct tpacket_req3 req;
   memset(&req, 0, sizeof(req));

   req.tp_block_size = m_blocksize;
   req.tp_block_nr = m_blocknum;
   req.tp_frame_size = m_framesize;
   req.tp_frame_nr = (m_blocksize * m_blocknum) / m_framesize;

   req.tp_retire_blk_tov = 60; // timeout in msec
   req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

   int ssopt_rx_ring = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *) &req, sizeof(req));
   if (ssopt_rx_ring == -1) {
      ::close(sock);
      throw PluginError(std::string("failed to enable RX_RING for AF_PACKET: ") + strerror(errno));
   }

   size_t mmap_bufsize = static_cast<size_t>(req.tp_block_size) * req.tp_block_nr;
   uint8_t *buffer = static_cast<uint8_t *>(mmap(NULL, mmap_bufsize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, sock, 0));
   if (buffer == MAP_FAILED) {
      ::close(sock);
      throw PluginError(std::string("mmap() failed: ") + strerror(errno));
   }

   struct iovec *rd = static_cast<struct iovec *>(malloc(req.tp_block_nr * sizeof(struct iovec)));
   if (rd == nullptr) {
      munmap(buffer, mmap_bufsize);
      ::close(sock);
      throw PluginError("not enough memory");
   }
   for (uint32_t i = 0; i < req.tp_block_nr; ++i) {
      rd[i].iov_base = buffer + (i * req.tp_block_size);
      rd[i].iov_len = req.tp_block_size;
   }

   struct sockaddr_ll bind_addr;
   memset(&bind_addr, 0, sizeof(bind_addr));
   bind_addr.sll_family = PF_PACKET;
   bind_addr.sll_protocol = htons(ETH_P_ALL);
   bind_addr.sll_ifindex = ifc_num;
   bind_addr.sll_hatype = 0;
   bind_addr.sll_pkttype = 0;
   bind_addr.sll_halen = 0;

   int bind_res = bind(sock, (struct sockaddr *) &bind_addr, sizeof(bind_addr));
   if (bind_res == -1) {
      munmap(buffer, mmap_bufsize);
      ::close(sock);
      free(rd);
      throw PluginError(std::string("bind failed: ") + strerror(errno));
   }

   if (m_fanout) {
      int fanout_type = PACKET_FANOUT_CPU;
      int fanout_arg = (m_fanout | (fanout_type << 16));
      int setsockopt_fanout = setsockopt(sock, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));
      if (setsockopt_fanout == -1) {
         munmap(buffer, mmap_bufsize);
         ::close(sock);
         free(rd);
         throw PluginError(std::string("fanout failed: ") + strerror(errno));
      }
   }

   memset(&m_pfd, 0, sizeof(m_pfd));
   m_pfd.fd = sock;
   m_pfd.events = POLLIN | POLLERR;
   m_pfd.revents = 0;

   m_sock = sock;
   m_rd = rd;
   m_buffer_size = mmap_bufsize;
   m_buffer = buffer;
   m_block_idx = 0;

   m_pbd = (struct tpacket_block_desc *) m_rd[m_block_idx].iov_base;
}

bool RawReader::get_block()
{
   if ((m_pbd->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
      // No data available at the moment
      if (poll(&m_pfd, 1, 0) == -1) {
         throw PluginError(std::string("poll: ") + strerror(errno));
      }
      return false;
   }
   return true;
}

void RawReader::return_block()
{
   m_pbd->hdr.bh1.block_status = TP_STATUS_KERNEL;
   m_block_idx = (m_block_idx + 1) % m_blocknum;
   m_pbd = (struct tpacket_block_desc *) m_rd[m_block_idx].iov_base;
}

int RawReader::read_packets(PacketBlock &packets)
{
   int read_cnt = 0;

   if (m_pkts_left) {
      read_cnt = process_packets(m_pbd, packets);
      if (!m_pkts_left) {
         return_block();
      }
      if (packets.cnt == packets.size) {
         return read_cnt;
      }
   }
   if (!get_block()) {
      return 0;
   }

   read_cnt += process_packets(m_pbd, packets);
   if (!m_pkts_left) {
      return_block();
   }
   return read_cnt;
}

int RawReader::process_packets(struct tpacket_block_desc *pbd, PacketBlock &packets)
{
   parser_opt_t opt = {&packets, false, false, DLT_EN10MB};
   uint32_t num_pkts = pbd->hdr.bh1.num_pkts;
   uint32_t capacity = RAW_PACKET_BLOCK_SIZE - packets.cnt;
   uint32_t to_read = 0;
   struct tpacket3_hdr *ppd;

   if (m_pkts_left) {
      ppd = m_last_ppd;
      to_read = (m_pkts_left >= capacity ? capacity : m_pkts_left);
      m_pkts_left = m_pkts_left - to_read;
   } else {
      ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd + pbd->hdr.bh1.offset_to_first_pkt);
      to_read = (num_pkts >= capacity ? capacity : num_pkts);
      m_pkts_left = num_pkts - to_read;
   }

   for (uint32_t i = 0; i < to_read; ++i) {
      const u_char *data = (uint8_t *) ppd + ppd->tp_mac;
      size_t len = ppd->tp_len;
      size_t snaplen = ppd->tp_snaplen;
      struct timeval ts = {ppd->tp_sec, ppd->tp_nsec / 1000};

      parse_packet(&opt, ts, data, len, snaplen);
      ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd + ppd->tp_next_offset);
   }
   m_last_ppd = ppd;

   return to_read;
}

void RawReader::print_available_ifcs()
{
   struct ifaddrs *ifaddr;

   if (getifaddrs(&ifaddr) == -1) {
      throw PluginError(strerror(errno));
   }

   if (ifaddr == nullptr) {
      std::cout << "No available interfaces found" << std::endl;
   } else {
      std::cout << "List of available interfaces:" << std::endl;
   }

   size_t idx = 1;
   for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr == NULL) {
         continue;
      }

      std::cout << idx++ << ".   " << ifa->ifa_name << std::endl;
   }

   freeifaddrs(ifaddr);
   throw PluginExit();
}

InputPlugin::Result RawReader::get(PacketBlock &packets)
{
   int ret;

   packets.cnt = 0;
   ret = read_packets(packets);
   if (ret == 0) {
      return Result::TIMEOUT;
   }
   if (ret < 0) {
      throw PluginError("error during reading from socket");
   }

   m_seen += ret;
   m_parsed += packets.cnt;
   return packets.cnt ? Result::PARSED : Result::NOT_PARSED;
 }

}
