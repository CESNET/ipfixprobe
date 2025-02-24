/**
 * @file
 * @brief Packet reader using raw sockets
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 * 
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <ipfixprobe.hpp>
#include <cstdint>
#include <string>
#include <linux/if_packet.h>

#include <poll.h>


namespace ipxp {

class RawReader : public InputPlugin {
public:
   RawReader(const std::string& params);
   ~RawReader();
   void close();
   std::string get_name() const { return "raw"; }
   InputPlugin::Result get(PacketBlock &packets);

   OptionsParser *get_parser() const;

private:

   void init(const char *params);


   int m_sock;
   uint16_t m_fanout;
   struct iovec *m_rd;
   struct pollfd m_pfd;

   uint8_t *m_buffer;
   uint32_t m_buffer_size;

   uint32_t m_block_idx;
   uint32_t m_blocksize;
   uint32_t m_framesize;
   uint32_t m_blocknum;

   struct tpacket3_hdr *m_last_ppd;
   struct tpacket_block_desc *m_pbd;
   uint32_t m_pkts_left;

   void open_ifc(const std::string &ifc);
   bool get_block();
   void return_block();
   int read_packets(PacketBlock &packets);
   int process_packets(struct tpacket_block_desc *pbd, PacketBlock &packets);
   void print_available_ifcs();
};

void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data);

} // namespace ipxp
