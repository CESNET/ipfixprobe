/**
 * \file flow_meter.cpp
 * \brief Main file of the flow_meter module.
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
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
#include <getopt.h>
#include <string>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <stdlib.h>

#include "flow_meter.h"
#include "packet.h"
#include "flowifc.h"
#include "pcapreader.h"
#include "nhtflowcache.h"
#include "unirecexporter.h"
#include "ipfixexporter.h"
#include "stats.h"
#include "fields.h"
#include "conversion.h"

#include "httpplugin.h"
#include "rtspplugin.h"
#include "httpsplugin.h"
#include "dnsplugin.h"
#include "sipplugin.h"
#include "ntpplugin.h"
#include "arpplugin.h"
#include "passivednsplugin.h"
#include "smtpplugin.h"
#include "pstatsplugin.h"
#include "ovpnplugin.h"
#include "ssdpplugin.h"
#include "dnssdplugin.h"

using namespace std;

trap_module_info_t *module_info = NULL;
static int stop = 0;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("flow_meter", "Convert packets from PCAP file or network interface into biflow records.", 0, -1)

#define SUPPORTED_PLUGINS_LIST "http,rtsp,https,dns,sip,ntp,smtp,basic,arp,passivedns,pstats,ssdp,dnssd,ovpn"

// TODO: remove parameters when using ndp
#define MODULE_PARAMS(PARAM) \
  PARAM('p', "plugins", "Activate specified parsing plugins. Output interface for each plugin correspond the order which you specify items in -i and -p param. "\
  "For example: \'-i u:a,u:b,u:c -p http,basic,dns\' http traffic will be send to interface u:a, basic flow to u:b etc. If you don't specify -p parameter, flow meter"\
  " will require one output interface for basic flow by default. Format: plugin_name[,...] Supported plugins: " SUPPORTED_PLUGINS_LIST \
  " Some plugins have features activated with additional parameters. Format: plugin_name[:plugin_param=value[:...]][,...] If plugin does not support parameters, any parameters given will be ignored."\
  " Supported plugin parameters are listed in README", required_argument, "string")\
  PARAM('c', "count", "Quit after number of packets are captured.", required_argument, "uint32")\
  PARAM('I', "interface", "Capture from given network interface. Parameter require interface name (eth0 for example). For nfb interface you can channel after interface delimited by : (/dev/nfb0:1) default is 0", required_argument, "string")\
  PARAM('r', "file", "Pcap file to read. - to read from stdin.", required_argument, "string") \
  PARAM('n', "no_eof", "Don't send NULL record message when flow_meter exits.", no_argument, "none") \
  PARAM('l', "snapshot_len", "Snapshot length when reading packets. Set value between 120-65535.", required_argument, "uint32") \
  PARAM('t', "timeout", "Active and inactive timeout in seconds. Format: DOUBLE:DOUBLE. Value default means use default value 300.0:30.0.", required_argument, "string") \
  PARAM('s', "cache_size", "Size of flow cache. Parameter is used as an exponent to the power of two. Valid numbers are in range 4-30. default is 17 (131072 records).", required_argument, "string") \
  PARAM('S', "cache-statistics", "Print flow cache statistics. NUMBER specifies interval between prints.", required_argument, "float") \
  PARAM('P', "pcap-statistics", "Print pcap statistics every 5 seconds. The statistics do not behave the same way on all platforms.", no_argument, "none") \
  PARAM('L', "link_bit_field", "Link bit field value.", required_argument, "uint64") \
  PARAM('D', "dir_bit_field", "Direction bit field value.", required_argument, "uint8") \
  PARAM('F', "filter", "String containing filter expression to filter traffic. See man pcap-filter.", required_argument, "string") \
  PARAM('O', "odid", "Send ODID field instead of LINK_BIT_FIELD in unirec message.", no_argument, "none") \
  PARAM('x', "ipfix", "Export to IPFIX collector. Format: HOST:PORT or [HOST]:PORT", required_argument, "string") \
  PARAM('u', "udp", "Use UDP when exporting to IPFIX collector.", no_argument, "none")

/**
 * \brief Parse input plugin settings.
 * \param [in] settings String containing input plugin settings.
 * \param [out] plugins Array for storing active plugins.
 * \param [in] module_options Options for plugin initialization.
 * \return Number of items specified in input string.
 */
int parse_plugin_settings(const string &settings, vector<FlowCachePlugin *> &plugins, options_t &module_options)
{
   string proto, params;
   size_t begin = 0, end = 0, begin_params = 0;

   int ifc_num = 0;
   while (end != string::npos) { // Iterate through user specified settings.
      end = settings.find(",", begin);
      proto = settings.substr(begin, (end == string::npos ? (settings.length() - begin) : (end - begin)));

      begin_params = proto.find(":");
      params = proto.substr((begin_params == string::npos ? (proto.length()) : (begin_params + 1)), proto.length());
      proto = (begin_params == string::npos ? (proto) : (proto.substr(0, begin_params)));

      if (proto == "basic") {
         module_options.basic_ifc_num = ifc_num++; // Enable parsing basic flow (flow without any plugin output).
      } else if (proto == "http") {
         vector<plugin_opt> tmp;
         // Register extension header identifiers.
         // New configuration support sending plugin output to specific libtrap interface (e.g. http to ifc 1, dns to ifc 2...)
         // so it is necessary store extension-header -> output interface mapping within plugin.

         tmp.push_back(plugin_opt("http", http, ifc_num++));

         plugins.push_back(new HTTPPlugin(module_options, tmp));
      } else if (proto == "rtsp") {
         vector<plugin_opt> tmp;

         tmp.push_back(plugin_opt("rtsp", rtsp, ifc_num++));

         plugins.push_back(new RTSPPlugin(module_options, tmp));
      } else if (proto == "https") {
         vector<plugin_opt> tmp;

         tmp.push_back(plugin_opt("https", https, ifc_num++));

         plugins.push_back(new HTTPSPlugin(module_options, tmp));
      } else if (proto == "dns"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("dns", dns, ifc_num++));

         plugins.push_back(new DNSPlugin(module_options, tmp));
      } else if (proto == "sip"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("sip", sip, ifc_num++));

         plugins.push_back(new SIPPlugin(module_options, tmp));
      } else if (proto == "ntp"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("ntp", ntp, ifc_num++));

         plugins.push_back(new NTPPlugin(module_options, tmp));
      } else if (proto == "smtp"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("smtp", smtp, ifc_num++));

         plugins.push_back(new SMTPPlugin(module_options, tmp));
      } else if (proto == "arp"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("arp", arp, ifc_num++));

         plugins.push_back(new ARPPlugin(module_options, tmp));
      } else if (proto == "passivedns"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("passivedns", passivedns, ifc_num++));

         plugins.push_back(new PassiveDNSPlugin(module_options, tmp));
      } else if (proto == "pstats"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("pstats", pstats, ifc_num++));

         plugins.push_back(new PSTATSPlugin(module_options, tmp));
      } else if (proto == "ovpn"){
          vector<plugin_opt> tmp;
          tmp.push_back(plugin_opt("ovpn", ovpn, ifc_num++));

          plugins.push_back(new OVPNPlugin(module_options, tmp));
      } else if (proto == "ssdp"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("ssdp", ssdp, ifc_num++));

         plugins.push_back(new SSDPPlugin(module_options, tmp));
      } else if (proto == "dnssd"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("dnssd", dnssd, ifc_num++, params));

         plugins.push_back(new DNSSDPlugin(module_options, tmp));
      } else {
         fprintf(stderr, "Unsupported plugin: \"%s\"\n", proto.c_str());
         return -1;
      }
      begin = end + 1;
   }

   return ifc_num;
}

/**
 * \brief Count trap interfaces.
 * \param [in] argc Number of parameters.
 * \param [in] argv Pointer to parameters.
 * \return Number of trap interfaces.
 */
int count_trap_interfaces(int argc, char *argv[])
{
   char *interfaces = NULL;
   for (int i = 1; i < argc; i++) { // Find argument for param -i.
      if (!strcmp(argv[i], "-i") && i + 1 < argc) {
         interfaces = argv[i + 1];
      }
   }
   int ifc_cnt = 1;
   if (interfaces != NULL) {
      while(*interfaces) { // Count number of specified interfaces.
         if (*(interfaces++) == ',') {
            ifc_cnt++;
         }
      }
      return ifc_cnt;
   }

   return ifc_cnt;
}

/**
 * \brief Convert double to struct timeval.
 * \param [in] value Value to convert.
 * \param [out] time Struct for storing converted time.
 */
static inline void double_to_timeval(double value, struct timeval &time)
{
   time.tv_sec = (long) value;
   time.tv_usec = (value - (long) value) * 1000000;
}

/**
 * \brief Exit and print an error message.
 * \param [in] e String containing an error message
 * \return EXIT_FAILURE
 */
inline bool error(const string &e)
{
   cerr << "flow_meter: " << e << endl;
   return EXIT_FAILURE;
}

/**
 * \brief Signal handler function.
 * \param [in] sig Signal number.
 */
void signal_handler(int sig)
{
   stop = 1;
}

int main(int argc, char *argv[])
{
   plugins_t plugin_wrapper;
   options_t options;
   options.flow_cache_size = DEFAULT_FLOW_CACHE_SIZE;
   options.flow_line_size = DEFAULT_FLOW_LINE_SIZE;
   double_to_timeval(DEFAULT_INACTIVE_TIMEOUT, options.inactive_timeout);
   double_to_timeval(DEFAULT_ACTIVE_TIMEOUT, options.active_timeout);
   options.print_stats = true; /* Plugins, FlowCache stats ON. */
   options.print_pcap_stats = false;
   options.interface = "";
   options.basic_ifc_num = 0;
   options.snaplen = 0;
   options.eof = true;

#ifndef DISABLE_UNIREC
   bool odid = false;
#endif
   bool export_unirec = false, export_ipfix = false, help = false, udp = false;
   int ifc_cnt = 0, verbose = -1;
   uint64_t link = 1;
   uint32_t pkt_limit = 0; /* Limit of packets for packet parser. 0 = no limit */
   uint8_t dir = 0;
   string host = "", port = "", filter = "";

   for (int i = 0; i < argc; i++) {
      if (!strcmp(argv[i], "-i")) {
         export_unirec = true;
      } else if (!strcmp(argv[i], "-x") || !strcmp(argv[i], "--ipfix")) {
         export_ipfix = true;
      } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
         help = true;
      } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "-vv") || !strcmp(argv[i], "-vvv")) {
         if (verbose >= 0) {
            for (int j = verbose; j + 1 < argc; j++) {
               argv[j] = argv[j + 1];
            }
            argc--;
            verbose = --i;
         } else {
            verbose = i;
         }
      }
   }

   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

   if ((export_unirec && !export_ipfix) || help) {
      /* TRAP initialization */
      ifc_cnt = count_trap_interfaces(argc, argv);
      module_info->num_ifc_out = ifc_cnt;
#ifndef DISABLE_UNIREC
      TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
#else
      puts("ipfixprobe version " VERSION);
      puts("ipfixprobe is a simplified flow exporter (flow_meter) without libtrap&UniRec support.");
      puts("");
      puts("Usage: ipfixprobe [-I interface] -x host:port [-u] [-p " SUPPORTED_PLUGINS_LIST "] [-r file]");
      puts("");
#endif
   } else if (verbose >= 0) {
      for (int i = verbose; i + 1 < argc; i++) {
         argv[i] = argv[i + 1];
      }
      argc--;
   }

   if (export_unirec && export_ipfix) {
#ifndef DISABLE_UNIREC
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
#endif
      return error("Cannot export to IPFIX and Unirec at the same time.");
   } else if (!export_unirec && !export_ipfix) {
#ifndef DISABLE_UNIREC
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
#endif
      return error("Specify exporter output Unirec (-i) or IPFIX (-x/--ipfix).");
   }

   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   signal(SIGPIPE, SIG_IGN);

   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'p':
         {
            options.basic_ifc_num = -1;
            int ret = parse_plugin_settings(string(optarg), plugin_wrapper.plugins, options);
            if (ret < 0) {
#ifndef DISABLE_UNIREC
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -p");
            }
            if (ifc_cnt && ret != ifc_cnt) {
#ifndef DISABLE_UNIREC
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Number of output ifc interfaces does not correspond number of items in -p parameter.");
            }
         }
         break;
      case 'c':
         {
            uint32_t tmp;
            if (!str_to_uint32(optarg, tmp)) {
#ifndef DISABLE_UNIREC
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -c");
            }
            pkt_limit = tmp;
         }
         break;
      case 'I':
         options.interface = string(optarg);
         break;
      case 't':
         {
            if (!strcmp(optarg, "default")) {
               break;
            }

            char *check;
            check = strchr(optarg, ':');
            if (check == NULL) {
#ifndef DISABLE_UNIREC
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -t");
            }

            *check = '\0';
            double tmp1, tmp2;
            if (!str_to_double(optarg, tmp1) || !str_to_double(check + 1, tmp2) || tmp1 < 0 || tmp2 < 0) {
#ifndef DISABLE_UNIREC
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -t");
            }

            double_to_timeval(tmp1, options.active_timeout);
            double_to_timeval(tmp2, options.inactive_timeout);
         }
         break;
      case 'r':
         options.pcap_file = string(optarg);
         break;
      case 'n':
         options.eof = false;
         break;
      case 'l':
         if (!str_to_uint32(optarg, options.snaplen)) {
#ifndef DISABLE_UNIREC
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
#endif
            return error("Invalid argument for option -l");
         }
         if (options.snaplen < MIN_SNAPLEN) {
            printf("Setting snapshot length to minimum value %d.\n", MIN_SNAPLEN);
            options.snaplen = MIN_SNAPLEN;
         } else if (options.snaplen > MAX_SNAPLEN) {
            printf("Setting snapshot length to maximum value %d.\n", MAX_SNAPLEN);
            options.snaplen = MAX_SNAPLEN;
         }
         break;
      case 's':
         if (strcmp(optarg, "default")) {
            uint32_t tmp;
            if (!str_to_uint32(optarg, tmp) || tmp <= 3 || tmp > 30) {
#ifndef DISABLE_UNIREC
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -s");
            }

            options.flow_cache_size = (1 << tmp);
         } else {
            options.flow_cache_size = DEFAULT_FLOW_CACHE_SIZE;
         }
         break;
      case 'S':
         {
            double tmp;
            if (!str_to_double(optarg, tmp)) {
#ifndef DISABLE_UNIREC
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -S");
            }
            double_to_timeval(tmp, options.cache_stats_interval);
            options.print_stats = false; /* Plugins, FlowCache stats OFF.*/
         }
         break;
      case 'P':
         options.print_pcap_stats = true;
         break;
      case 'L':
         if (!str_to_uint64(optarg, link)) {
#ifndef DISABLE_UNIREC
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
#endif
            return error("Invalid argument for option -L");
         }
         break;
      case 'D':
         if (!str_to_uint8(optarg, dir)) {
#ifndef DISABLE_UNIREC
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
#endif
            return error("Invalid argument for option -D");
         }
         break;
      case 'F':
         filter = string(optarg);
         break;
      case 'O':
#ifndef DISABLE_UNIREC
         odid = true;
#endif
         break;
      case 'x':
         {
            host = optarg;
            size_t tmp = host.find_last_of(":");
            if (tmp == string::npos) {
#ifndef DISABLE_UNIREC
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -x");
            }


            port = string(host, tmp + 1);
            host = host.erase(tmp);
            trim_str(host);
            trim_str(port);

            if (host == "" || port == "") {
#ifndef DISABLE_UNIREC
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -x");
            }

            if (host[0] == '[' && host[host.size() - 1] == ']') {
               host = host.erase(0, 1);
               host = host.erase(host.size() - 1, 1);
            }
         }
         break;
      case 'u':
         udp = true;
         break;
      default:
#ifndef DISABLE_UNIREC
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
#endif
         return error("Invalid arguments");
      }
   }

   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

   if (options.interface != "" && options.pcap_file != "") {
#ifndef DISABLE_UNIREC
      TRAP_DEFAULT_FINALIZATION();
#endif
      return error("Cannot capture from file and from interface at the same time.");
   } else if (options.interface == "" && options.pcap_file == "") {
#ifndef DISABLE_UNIREC
      TRAP_DEFAULT_FINALIZATION();
#endif
      return error("Specify capture interface (-I) or file for reading (-r). ");
   }

   bool parse_every_pkt = false;
   uint32_t max_payload_size = 0;

   for (unsigned int i = 0; i < plugin_wrapper.plugins.size(); i++) {
      /* Check if plugins need all packets. */
      if (!plugin_wrapper.plugins[i]->include_basic_flow_fields()) {
         parse_every_pkt = true;
      }
      /* Get max payload size from plugins. */
      if (max_payload_size < plugin_wrapper.plugins[i]->max_payload_length()) {
         max_payload_size = plugin_wrapper.plugins[i]->max_payload_length();
      }
   }

   if (options.snaplen == 0) { /* Check if user specified snapshot length. */
      int max_snaplen = max_payload_size + MIN_SNAPLEN;
      if (max_snaplen > MAXPCKTSIZE) {
         max_snaplen = MAXPCKTSIZE;
      }
      options.snaplen = max_snaplen;
   }

   PacketReceiver *packetloader;

#ifdef HAVE_NDP
   packetloader = new NdpPacketReader(options);
#else /* HAVE_NDP */
   packetloader = new PcapReader(options);
#endif /* HAVE_NDP */

   if (options.interface == "") {
      if (packetloader->open_file(options.pcap_file, parse_every_pkt) != 0) {
#ifndef DISABLE_UNIREC
         TRAP_DEFAULT_FINALIZATION();
#endif
         return error("Can't open input file: " + options.pcap_file);
      }
   } else {
#ifndef DISABLE_UNIREC
      if (export_unirec) {
         for (int i = 0; i < ifc_cnt; i++) {
            trap_ifcctl(TRAPIFC_OUTPUT, i, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);
         }
      }
#endif

      if (packetloader->init_interface(options.interface, options.snaplen, parse_every_pkt) != 0) {
#ifndef DISABLE_UNIREC
         TRAP_DEFAULT_FINALIZATION();
#endif
         return error("Unable to initialize libpcap: " + packetloader->error_msg);
      }
   }

   if (filter != "") {
      if (packetloader->set_filter(filter) != 0) {
#ifndef DISABLE_UNIREC
         TRAP_DEFAULT_FINALIZATION();
#endif
         return error(packetloader->error_msg);
      }
   }

   NHTFlowCache flowcache(options);
#ifndef DISABLE_UNIREC
   UnirecExporter flowwriter(options.eof);
#endif
   IPFIXExporter flow_writer_ipfix;

   if (export_unirec) {
#ifndef DISABLE_UNIREC
      if (flowwriter.init(plugin_wrapper.plugins, ifc_cnt, options.basic_ifc_num, link, dir, odid) != 0) {
         TRAP_DEFAULT_FINALIZATION();
         return error("Unable to initialize UnirecExporter.");
      }
      flowcache.set_exporter(&flowwriter);
#endif
   } else {
      if (flow_writer_ipfix.init(plugin_wrapper.plugins, options.basic_ifc_num, link, host, port, udp, (verbose >= 0), dir) != 0) {
#ifndef DISABLE_UNIREC
         TRAP_DEFAULT_FINALIZATION();
#endif
         return error("Unable to initialize IPFIXExporter.");
      }
      flowcache.set_exporter(&flow_writer_ipfix);
   }

   if (!options.print_stats) {
      plugin_wrapper.plugins.push_back(new StatsPlugin(options.cache_stats_interval, cout));
   }

   for (unsigned int i = 0; i < plugin_wrapper.plugins.size(); i++) {
      flowcache.add_plugin(plugin_wrapper.plugins[i]);
   }

   flowcache.init();

   Packet packet;
   int ret = 0;
   uint64_t pkt_total = 0, pkt_parsed = 0;

   packet.packet = new char[MAXPCKTSIZE + 1];

   /* Main packet capture loop. */
   while (!stop && (ret = packetloader->get_pkt(packet)) > 0) {
      if (ret == 3) { /* Process timeout. */
         flowcache.export_expired(time(NULL));
         continue;
      }

      pkt_total++;

      if (ret == 2) {
         flowcache.put_pkt(packet);
         pkt_parsed++;

         /* Check if packet limit is reached. */
         if (pkt_limit != 0 && pkt_parsed >= pkt_limit) {
            break;
         }
      }
   }

   if (options.print_stats) {
      packetloader->printStats();
   }

   if (ret < 0) {
      packetloader->close();
#ifndef DISABLE_UNIREC
      flowwriter.close();
#endif
      delete [] packet.packet;
#ifndef DISABLE_UNIREC
      TRAP_DEFAULT_FINALIZATION();
#endif
      return error("Error during reading: " + packetloader->error_msg);
   }

   /* Cleanup. */
   flowcache.finish();
#ifndef DISABLE_UNIREC
   flowwriter.close();
#endif
   packetloader->close();
   delete packetloader;
   delete [] packet.packet;
#ifndef DISABLE_UNIREC
   TRAP_DEFAULT_FINALIZATION();
#endif

   return EXIT_SUCCESS;
}
