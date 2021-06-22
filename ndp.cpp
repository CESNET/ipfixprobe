/**
 * \file ndp.cpp
 * \brief Packet reader using NDP library for high speed capture.
 * \author Tomas Benes <benesto@fit.cvut.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
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
#ifdef HAVE_NDP

#include <cstdio>
#include <cstring>
#include <iostream>

#include "ndp.h"
#include "parser.h"

void packet_ndp_handler(parser_opt_t *opt, const struct ndp_packet *ndp_packet, const struct ndp_header *ndp_header)
{
   struct timeval ts;
   ts.tv_sec = ndp_header->timestamp_sec;
   ts.tv_usec = ndp_header->timestamp_nsec / 1000;

   parse_packet(opt, ts, ndp_packet->data, ndp_packet->data_length, ndp_packet->data_length);
}

NdpPacketReader::NdpPacketReader() : print_pcap_stats(false)
{
   processed = 0;
   parsed = 0;
}

NdpPacketReader::NdpPacketReader(const options_t &options)
{
   processed = 0;
   parsed = 0;
   print_pcap_stats = options.print_pcap_stats;
}

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

int NdpPacketReader::get_pkt(PacketBlock &packets)
{
   int ret = -1;
   if (print_pcap_stats) {
      //print_stats();
   }

   struct ndp_packet *ndp_packet;
   struct ndp_header *ndp_header;

   parser_opt_t opt = {&packets, false, parse_all, 0};
   size_t read_pkts = 0;
   for (unsigned i = 0; i < packets.size; i++) {
      ret = ndpReader.get_pkt(&ndp_packet, &ndp_header);
      if (ret == 0) {
         if (opt.pkts->cnt) {
            break;
         }
         return 3;
      } else if (ret < 0) {
         // Error occured.
         error_msg = ndpReader.error_msg;
         return ret;
      }
      read_pkts++;
      packet_ndp_handler(&opt, ndp_packet, ndp_header);
   }
   processed += read_pkts;
   parsed += opt.pkts->cnt;

   if (opt.pkts->cnt) {
      // Packets are valid and ready to be process by flow_cache.
      return 2;
   }
   return 1;
}

#endif /* HAVE_NDP */

