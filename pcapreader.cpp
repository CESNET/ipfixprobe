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

#ifndef HAVE_NDP
#include <pcap/pcap.h>
#endif /* HAVE_NDP */

#include "pcapreader.h"
#include "parser.h"

// Read timeout in miliseconds for pcap_open_live function.
#define READ_TIMEOUT 1000

// Interval between pcap handle stats print in seconds.
#define STATS_PRINT_INTERVAL  5

#ifndef HAVE_NDP

/**
 * \brief Parsing callback function for pcap_dispatch() call. Parse packets up to transport layer.
 * \param [in,out] arg Serves for passing pointer to Packet structure into callback function.
 * \param [in] h Contains timestamp and packet size.
 * \param [in] data Pointer to the captured packet data.
 */
void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data)
{
#ifdef __CYGWIN__
   // WinPcap, uses Microsoft's definition of struct timeval, which has `long` data type
   // used for both tv_sec and tv_usec and has 32 bit even on 64 bit platform.
   // Cygwin uses 64 bit tv_sec and tv_usec, thus a little reinterpretation of bytes needs to be used.
   struct pcap_pkthdr new_h;
   new_h.ts.tv_sec = *(uint32_t *) h;
   new_h.ts.tv_usec = *(((uint32_t *) h) + 1);
   new_h.caplen = *((uint32_t *) h + 2);
   new_h.len = *((uint32_t *) h + 3);
   parse_packet((parser_opt_t *) arg, new_h.ts, data, new_h.len, new_h.caplen);
#else
   parse_packet((parser_opt_t *) arg, h->ts, data, h->len, h->caplen);
#endif
}

static void print_libpcap_stats(pcap_t *handle)
{
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

PcapReader::PcapReader() : handle(NULL), print_pcap_stats(false), netmask(PCAP_NETMASK_UNKNOWN)
{
   processed = 0;
   parsed = 0;
}

PcapReader::PcapReader(const options_t &options) : handle(NULL), netmask(PCAP_NETMASK_UNKNOWN)
{
   print_pcap_stats = options.print_pcap_stats;
   last_ts.tv_sec = 0;
   last_ts.tv_usec = 0;
   processed = 0;
   parsed = 0;
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
int PcapReader::open_file(const std::string &file, bool parse_every_pkt)
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

   datalink = pcap_datalink(handle);
   if (datalink != DLT_EN10MB && datalink != DLT_LINUX_SLL) {
      error_msg = "Unsupported link type detected. Supported types are DLT_EN10MB and DLT_LINUX_SLL.";
      close();
      return 1;
   }

   live_capture = false;
   parse_all = parse_every_pkt;
   error_msg = "";
   return 0;
}

void PcapReader::print_interfaces()
{
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *devs;
   pcap_if_t *d;
   int max_width = 0;
   int i = 0;

   if (pcap_findalldevs(&devs, errbuf) == -1) {
      fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
      return;
   }

   if (devs != NULL) {
      printf("List of available interfaces:\n");
   }

   for (d = devs; d != NULL; d = d->next) {
      int len = strlen(d->name);
      if (len > max_width) {
         max_width = len;
      }
   }
   for (d = devs; d != NULL; d = d->next) {
      if (d->flags & PCAP_IF_UP) {
         printf("%2d.  %-*s", ++i, max_width, d->name);
         if (d->description) {
            printf("    %s\n", d->description);
         } else {
            printf("\n");
         }
      }
   }
   if (i == 0) {
      printf("No available interfaces found\n");
   }

   pcap_freealldevs(devs);
}

/**
 * \brief Initialize network interface for reading.
 * \param [in] interface Interface name.
 * \param [in] snaplen Snapshot length to be set on pcap handle.
 * \param [in] parse_every_pkt Try to parse every captured packet.
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int PcapReader::init_interface(const std::string &interface, int snaplen, bool parse_every_pkt)
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
      return 1;
   }
   if (errbuf[0] != 0) {
      fprintf(stderr, "%s\n", errbuf); // Print warning.
   }
   if (pcap_setnonblock(handle, 1, errbuf) < 0) {
      error_msg = errbuf;
      close();
      return 1;
   }

   datalink = pcap_datalink(handle);
   if (datalink != DLT_EN10MB && datalink != DLT_LINUX_SLL) {
      error_msg = "Unsupported link type detected. Supported types are DLT_EN10MB and DLT_LINUX_SLL.";
      close();
      return 1;
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
int PcapReader::set_filter(const std::string &filter_str)
{
   if (handle == NULL) {
      error_msg = "No live capture or file opened.";
      return 1;
   }

   struct bpf_program filter;
   if (pcap_compile(handle, &filter, filter_str.c_str(), 0, netmask) == -1) {
      error_msg = "Couldn't parse filter " + std::string(filter_str) + ": " + std::string(pcap_geterr(handle));
      return 1;
   }
   if (pcap_setfilter(handle, &filter) == -1) {
      pcap_freecode(&filter);
      error_msg = "Couldn't install filter " + std::string(filter_str) + ": " + std::string(pcap_geterr(handle));
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

int PcapReader::get_pkt(PacketBlock &packets)
{
   if (handle == NULL) {
      error_msg = "No live capture or file opened.";
      return -3;
   }

   int ret;

   if (print_pcap_stats) {
      //print_stats();
   }
   parser_opt_t opt = {&packets, false, parse_all, datalink};

   // Get pkt from network interface or file.
   ret = pcap_dispatch(handle, packets.size, packet_handler, (u_char *) (&opt));
   if (live_capture) {
      if (ret == 0) {
         return 3;
      }
      if (ret > 0) {
         processed += ret;
         parsed += opt.pkts->cnt;
         // Packet is valid and ready to process by flow_cache.
         return opt.packet_valid ? 2 : 1;
      }
   } else {
      if (opt.pkts->cnt) {
         processed += ret ? ret : opt.pkts->cnt;
         parsed += opt.pkts->cnt;
         return 2;
      }
   }
   if (ret < 0) {
      // Error occured.
      error_msg = pcap_geterr(handle);
   }
   return ret;
 }

#endif

