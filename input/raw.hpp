/**
 * \file raw.hpp
 * \brief Packet reader using raw sockets
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

#ifndef IPXP_INPUT_RAW_HPP
#define IPXP_INPUT_RAW_HPP

#include <config.h>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

class RawOptParser : public OptionsParser
{
public:
   std::string m_ifc;
   uint16_t m_fanout;
   uint32_t m_block_cnt;
   uint32_t m_pkt_cnt;
   bool m_list;

   RawOptParser() : OptionsParser("raw", "Input plugin for reading packets from a raw socket"),
      m_ifc(""), m_fanout(0), m_block_cnt(2048), m_pkt_cnt(32), m_list(false)
   {
      register_option("i", "ifc", "IFC", "Network interface name", [this](const char *arg){m_ifc = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("f", "fanout", "ID", "Enable packet fanout",
         [this](const char *arg){if (arg) {
            try {m_fanout = str2num<decltype(m_fanout)>(arg); if (!m_fanout) {return false;}} catch(std::invalid_argument &e) {return false;}
         } else {m_fanout = getpid() & 0xFFFF;} return true;},
         OptionFlags::OptionalArgument);
      register_option("b", "blocks", "SIZE", "Number of packet blocks (should be power of two num)",
         [this](const char *arg){try {m_block_cnt = str2num<decltype(m_block_cnt)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("p", "pkts", "SIZE", "Number of packets in block (should be power of two num)",
         [this](const char *arg){try {m_pkt_cnt = str2num<decltype(m_pkt_cnt)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("l", "list", "", "Print list of available interfaces", [this](const char *arg){m_list = true; return true;}, OptionFlags::NoArgument);
   }
};

class RawReader : public InputPlugin
{
public:
   RawReader();
   ~RawReader();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new RawOptParser(); }
   std::string get_name() const { return "raw"; }
   InputPlugin::Result get(PacketBlock &packets);

private:
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

}
#endif /* IPXP_INPUT_RAW_HPP */
