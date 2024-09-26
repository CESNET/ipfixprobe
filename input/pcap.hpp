/**
 * \file pcap.hpp
 * \brief Pcap reader based on libpcap
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

#ifndef IPXP_INPUT_PCAP_HPP
#define IPXP_INPUT_PCAP_HPP

#include <pcap/pcap.h>

#include <ipfixprobe/input.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

/*
 * \brief Minimum snapshot length of pcap handle.
 */
#define MIN_SNAPLEN  120

/*
 * \brief Maximum snapshot length of pcap handle.
 */
#define MAX_SNAPLEN  65535

// Read timeout in miliseconds for pcap_open_live function.
#define READ_TIMEOUT 1000

class PcapOptParser : public OptionsParser
{
public:
   std::string m_file;
   std::string m_ifc;
   std::string m_filter;
   uint16_t m_snaplen;
   uint64_t m_id;
   bool m_list;

   PcapOptParser() : OptionsParser("pcap", "Input plugin for reading packets from a pcap file or a network interface"),
      m_file(""), m_ifc(""), m_filter(""), m_snaplen(-1), m_id(0), m_list(false)
   {
      register_option("f", "file", "PATH", "Path to a pcap file", [this](const char *arg){m_file = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("i", "ifc", "IFC", "Network interface name", [this](const char *arg){m_ifc = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("F", "filter", "STR", "Filter string", [this](const char *arg){m_filter = arg; return true;}, OptionFlags::RequiredArgument);
      register_option("s", "snaplen", "SIZE", "Snapshot length in bytes (live capture only)",
         [this](const char *arg){try {m_snaplen = str2num<decltype(m_snaplen)>(arg);} catch(std::invalid_argument &e) {return false;} return true;},
         OptionFlags::RequiredArgument);
      register_option("l", "list", "", "Print list of available interfaces", [this](const char *arg){m_list = true; return true;}, OptionFlags::NoArgument);
   }
};

/**
 * \brief Class for reading packets from file or network interface.
 */
class PcapReader : public InputPlugin
{
public:
   PcapReader();
   ~PcapReader();

   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new PcapOptParser(); }
   std::string get_name() const { return "pcap"; }
   InputPlugin::Result get(PacketBlock &packets);

private:
   pcap_t *m_handle;          /**< libpcap file handle */
   uint16_t m_snaplen;
   int m_datalink;
   bool m_live;               /**< Capturing from network interface */
   bpf_u_int32 m_netmask;       /**< Network mask. Used when setting filter */

   void open_file(const std::string &file);
   void open_ifc(const std::string &ifc);
   void set_filter(const std::string &filter_str);

   void check_datalink(int datalink);
   void print_available_ifcs();
};

void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data);

}
#endif /* IPXP_INPUT_PCAP_HPP */
