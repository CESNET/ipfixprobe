/**
 * \file ndpreader.h
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

#ifndef NDP_H
#define NDP_H

#ifdef HAVE_NDP

#include <config.h>
#include <ndpreader.hpp>

#include "ipfixprobe.h"
#include "packet.h"
#include "packetreceiver.h"

class NdpPacketReader : public PacketReceiver
{
public:
   NdpPacketReader();
   NdpPacketReader(const options_t &options);
   ~NdpPacketReader();
   int open_file(const string &file, bool parse_every_pkt);
   int init_interface(const string &interface, int snaplen, bool parse_every_pkt);
   int set_filter(const string &filter_str);
   void printStats();
   void close();
   int get_pkt(PacketBlock &packets);

private:
   bool print_pcap_stats;      /**< Print stats. */
   bool parse_all;

   NdpReader ndpReader;
};

void packet_ndp_handler(Packet *pkt, const struct ndp_packet *ndp_packet, const struct ndp_header *ndp_header);

#endif /* HAVE_NDP */
#endif /* NDP_H */
