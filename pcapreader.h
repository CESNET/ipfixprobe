/**
 * \file pcapreader.h
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

#ifndef PCAPREADER_H
#define PCAPREADER_H

#include <config.h>
#ifndef HAVE_NDP
#include <pcap/pcap.h>
#endif /* HAVE_NDP */

#include "ipfixprobe.h"
#include "packet.h"
#include "packetreceiver.h"

/*
 * \brief Minimum snapshot length of pcap handle.
 */
#define MIN_SNAPLEN  120

/*
 * \brief Maximum snapshot length of pcap handle.
 */
#define MAX_SNAPLEN  65535

#ifndef HAVE_NDP

/**
 * \brief Class for reading packets from file or network interface.
 */
class PcapReader : public PacketReceiver
{
public:
   PcapReader();
   PcapReader(const options_t &options);
   ~PcapReader();

   int open_file(const std::string &file, bool parse_every_pkt);
   int init_interface(const std::string &interface, int snaplen, bool parse_every_pkt);
   int set_filter(const std::string &filter_str);
   void print_stats();
   void printStats();
   void close();
   int get_pkt(PacketBlock &packets);

   static void print_interfaces();

private:
   pcap_t *handle;                  /**< libpcap file handler. */
   bool live_capture;               /**< PcapReader is capturing from network interface. */
   bool print_pcap_stats;           /**< Print pcap handle stats. */
   struct timeval last_ts;          /**< Last timestamp. */
   bpf_u_int32 netmask;             /**< Network mask. Used when setting filter. */
   int datalink;
   bool parse_all;
};

void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data);

#endif /* HAVE_NDP */

#endif
