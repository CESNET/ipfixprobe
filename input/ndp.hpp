/**
 * \file ndp.hpp
 * \brief Packet reader using NDP library for high speed capture.
 * \author Tomas Benes <benesto@fit.cvut.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2020-2021 CESNET
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

#ifndef IPXP_INPUT_NDP_HPP
#define IPXP_INPUT_NDP_HPP

#include <bits/types/struct_timeval.h>
#include <ndpreader.hpp>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

struct Metadata_CTT {
   timeval ts;
   uint16_t vlan_tci;
   bool vlan_vld : 1;
   bool vlan_stripped : 1;
   uint8_t ip_csum_status : 2;
   uint8_t l4_csum_status : 2;
   uint8_t parser_status : 2;
   uint8_t ifc;
   uint16_t filter_bitmap;
   uint8_t ctt_export_trig : 1;
   uint8_t ctt_rec_matched : 1;
   uint8_t ctt_rec_created : 1;
   uint8_t ctt_rec_deleted : 1;
   uint64_t flow_hash;
   uint8_t l2_len : 7;
   uint16_t l3_len : 9;
   uint8_t l4_len : 8;
   uint8_t l2_ptype : 4;
   uint8_t l3_ptype : 4;
   uint8_t l4_ptype : 4;
};

class NdpOptParser : public OptionsParser
{
public:
   std::string m_dev;
   uint64_t m_id;
   std::string m_metadata;

   NdpOptParser() : OptionsParser("ndp", "Input plugin for reading packets from a ndp device"), m_dev(""), m_id(0), m_metadata("")
   {
      register_option("d", "dev", "PATH", "Path to a device file", [this](const char *arg){m_dev = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("I", "id", "NUM", "Link identifier number",
         [this](const char *arg){try {m_id = str2num<decltype(m_id)>(arg);} catch(std::invalid_argument &e) {return false;} return true;}, OptionFlags::RequiredArgument);
      register_option("M", "meta", "Metadata type", "Choose metadata type if any", [this](const char *arg){m_metadata = arg; return true;}, OptionFlags::RequiredArgument);
   }
};

class NdpPacketReader : public InputPlugin
{
public:
   NdpPacketReader();
   ~NdpPacketReader();

   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new NdpOptParser(); }
   std::string get_name() const { return "ndp"; }
   InputPlugin::Result get(PacketBlock &packets);

   void configure_telemetry_dirs(
      std::shared_ptr<telemetry::Directory> plugin_dir, 
      std::shared_ptr<telemetry::Directory> queues_dir) override;

private:
   struct RxStats {
        uint64_t receivedPackets;
        uint64_t receivedBytes;
   };

   telemetry::Content get_queue_telemetry();

   NdpReader ndpReader;
   RxStats m_stats = {};

   bool m_ctt_metadata = false;

   void init_ifc(const std::string &dev);
   void parse_ctt_metadata(const ndp_packet *ndp_packet, Metadata_CTT &ctt);
};

}
#endif /* IPXP_INPUT_NDP_HPP */
