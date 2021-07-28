/**
 * \file main.cpp
 * \brief Main file of the ipfixprobe exporter.
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
#include <unistd.h>
#include <string>
#include <iostream>
#include <future>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <iomanip>
#include <stdlib.h>
#include <thread>
#include <sys/time.h>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include "ipfixprobe.h"
#include "packet.h"
#include "flowifc.h"
#include "pcapreader.h"
#include "ndp.h"
#include "nhtflowcache.h"
#include "unirecexporter.h"
#include "ipfixexporter.h"
#include "stats.h"
#include "conversion.h"
#include "ring.h"
#include "stacktrace.h"

#include "httpplugin.h"
#include "rtspplugin.h"
#include "tlsplugin.h"
#include "dnsplugin.h"
#include "sipplugin.h"
#include "ntpplugin.h"
#include "passivednsplugin.h"
#include "smtpplugin.h"
#include "pstatsplugin.h"
#include "ovpnplugin.h"
#include "ssdpplugin.h"
#include "dnssdplugin.h"
#include "idpcontentplugin.h"
#include "netbiosplugin.h"
#include "phistsplugin.h"
#include "bstatsplugin.h"
#include "basicplusplugin.h"
#include "wgplugin.h"

using namespace std;

#ifdef WITH_NEMEA
trap_module_info_t *module_info = NULL;
#endif

volatile sig_atomic_t stop = 0;
int terminate_export = 0;
int terminate_storage = 0;
int terminate_input = 0;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("ipfixprobe", "Convert packets from PCAP file or network interface into biflow records.", 0, -1)

#define SUPPORTED_PLUGINS_LIST "http,rtsp,tls,dns,sip,ntp,smtp,basic,passivedns,pstats,ssdp,dnssd,ovpn,idpcontent,netbios,basicplus,bstats,phists,wg"

// TODO: remove parameters when using ndp
#define MODULE_PARAMS(PARAM) \
  PARAM('p', "plugins", "Activate specified parsing plugins. Output interface (NEMEA only) for each plugin correspond the order which you specify items in -i and -p param. "\
  "For example: \'-i u:a,u:b,u:c -p http,basic,dns\' http traffic will be send to interface u:a, basic flow to u:b etc. If you don't specify -p parameter, ipfixprobe"\
  " will require one output interface for basic flow by default. Format: plugin_name[,...] Supported plugins: " SUPPORTED_PLUGINS_LIST \
  " Some plugins have features activated with additional parameters. Format: plugin_name[:plugin_param=value[:...]][,...] If plugin does not support parameters, any parameters given will be ignored."\
  " Supported plugin parameters are listed in README", required_argument, "string")\
  PARAM('c', "count", "Quit after number of packets on each input are captured.", required_argument, "uint64")\
  PARAM('h', "help", "Print this help.", no_argument, "none")\
  PARAM('I', "interface", "Capture from given network interface. Parameter require interface name (eth0 for example). For nfb interface you can specify channel after interface delimited by : (/dev/nfb0:1) default channel is 0", required_argument, "string")\
  PARAM('r', "file", "Pcap file to read. - to read from stdin.", required_argument, "string") \
  PARAM('n', "no_eof", "Don't send NULL record message on exit (for NEMEA output).", no_argument, "none") \
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
  PARAM('u', "udp", "Use UDP when exporting to IPFIX collector.", no_argument, "none") \
  PARAM('q', "iqueue", "Input queue size (default 64).", required_argument, "uint32") \
  PARAM('Q', "oqueue", "Output queue size (default 16536).", required_argument, "uint32") \
  PARAM('e', "fps", "Export max N flows per second.", required_argument, "uint32") \
  PARAM('m', "mtu", "Max size of IPFIX data packet payload to send.", required_argument, "uint16") \
  PARAM('V', "version", "Print version.", no_argument, "none")\
  PARAM('v', "verbose", "Increase verbosity of the output, it can be duplicated like -vv / -vvv.", no_argument, "none")

#define PRINT_HELP_PARAM(p_short_opt, p_long_opt, p_description, p_required_argument, p_argument_type) \
if (p_required_argument == no_argument) { \
   printf("  -%c, --%s\t\t\t%s\n", p_short_opt, p_long_opt, p_description); \
} else { \
   printf("  -%c, --%s=%s\t\t%s\n", p_short_opt, p_long_opt, p_argument_type, p_description); \
}

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
      } else if (proto == "tls") {
         vector<plugin_opt> tmp;

         tmp.push_back(plugin_opt("tls", tls, ifc_num++));

         plugins.push_back(new TLSPlugin(module_options, tmp));
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
      } else if (proto == "passivedns"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("passivedns", passivedns, ifc_num++));

         plugins.push_back(new PassiveDNSPlugin(module_options, tmp));
      } else if (proto == "pstats"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("pstats", pstats, ifc_num++, params));

         plugins.push_back(new PSTATSPlugin(module_options, tmp));
      } else if (proto == "ovpn"){
          vector<plugin_opt> tmp;
          tmp.push_back(plugin_opt("ovpn", ovpn, ifc_num++));

          plugins.push_back(new OVPNPlugin(module_options, tmp));
      } else if (proto == "idpcontent"){
          vector<plugin_opt> tmp;
          tmp.push_back(plugin_opt("idpcontent", idpcontent, ifc_num++));

          plugins.push_back(new IDPCONTENTPlugin(module_options, tmp));
      } else if (proto == "ssdp"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("ssdp", ssdp, ifc_num++));

         plugins.push_back(new SSDPPlugin(module_options, tmp));
      } else if (proto == "dnssd"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("dnssd", dnssd, ifc_num++, params));

         plugins.push_back(new DNSSDPlugin(module_options, tmp));
      } else if (proto == "netbios"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("netbios", netbios, ifc_num++, params));

         plugins.push_back(new NETBIOSPlugin(module_options, tmp));
      } else if (proto == "basicplus"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("basicplus", basicplus, ifc_num++, params));

         plugins.push_back(new BASICPLUSPlugin(module_options, tmp));
      } else if (proto == "bstats"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("bstats", bstats, ifc_num++, params));

         plugins.push_back(new BSTATSPlugin(module_options, tmp));
      } else if (proto == "phists"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("phists", phists, ifc_num++, params));
         plugins.push_back(new PHISTSPlugin(module_options, tmp));
      } else if (proto == "wg"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("wg", wg, ifc_num++, params));

         plugins.push_back(new WGPlugin(module_options, tmp));
      } else {
         fprintf(stderr, "Unsupported plugin: \"%s\"\n", proto.c_str());
         return -1;
      }
      begin = end + 1;
   }

   return ifc_num;
}

#ifdef WITH_NEMEA
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
#endif

struct InputStats {
   uint64_t packets;
   uint64_t parsed;
   uint64_t bytes;
   uint64_t qtime;
   bool error;
   std::string msg;
};

void input_thread(PacketReceiver *packetloader, PacketBlock *pkts, size_t block_cnt, uint64_t pkt_limit, ipx_ring_t *queue, std::promise<InputStats> *threadOutput)
{
   struct timespec start;
   struct timespec end;
   size_t i = 0;
   int ret;
   InputStats stats = {0, 0, 0, 0, false, ""};
   while (!terminate_input) {
      PacketBlock *block = &pkts[i];
      block->cnt = 0;
      block->bytes = 0;

      if (pkt_limit && packetloader->parsed + block->size >= pkt_limit) {
         if (packetloader->parsed >= pkt_limit) {
            break;
         }
         block->size = pkt_limit - packetloader->parsed;
      }
      ret = packetloader->get_pkt(*block);
      if (ret <= 0) {
         stats.error = ret < 0;
         stats.msg = packetloader->error_msg;
         break;
      } else if (ret == 3) { /* Process timeout. */
         usleep(1);
         continue;
      } else if (ret == 2) {
         stats.bytes += block->bytes;
         #ifdef __linux__
         const clockid_t clk_id = CLOCK_MONOTONIC_COARSE;
         #else
         const clockid_t clk_id = CLOCK_MONOTONIC;
         #endif
         clock_gettime(clk_id, &start);
         ipx_ring_push(queue, (void *) block);
         clock_gettime(clk_id, &end);

         int64_t time = end.tv_nsec - start.tv_nsec;
         if (start.tv_sec != end.tv_sec) {
            time += 1000000000;
         }
         stats.qtime += time;
         i = (i + 1) % block_cnt;
      }
   }
   stats.parsed = packetloader->parsed;
   stats.packets = packetloader->processed;
   threadOutput->set_value(stats);
}

struct StorageStats {
   bool error;
};

void storage_thread(FlowCache *cache, ipx_ring_t *queue, std::promise<StorageStats> *threadOutput)
{
   StorageStats stats = {false};
   while (1) {
      PacketBlock *block = static_cast<PacketBlock *>(ipx_ring_pop(queue));
      if (block) {
         for (unsigned i = 0; i < block->cnt; i++) {
            cache->put_pkt(block->pkts[i]);
         }
      } else if (terminate_storage && !ipx_ring_cnt(queue)) {
         break;
      } else {
         cache->export_expired(time(NULL));
         usleep(1);
      }
   }
   threadOutput->set_value(stats);
}

struct OutputStats {
   uint64_t biflows;
   uint64_t bytes;
   uint64_t packets;
   uint64_t dropped;
   bool error;
};

#define MICRO_SEC 1000000L
long timeval_diff(const struct timeval *start, const struct timeval *end)
{
    return (end->tv_sec - start->tv_sec) * MICRO_SEC
        + (end->tv_usec - start->tv_usec);
}

void export_thread(FlowExporter *exp, ipx_ring_t *queue, std::promise<OutputStats> *threadOutput, uint32_t fps)
{
   OutputStats stats = {0, 0, 0, 0, false};
   struct timespec sleep_time = {0};
   struct timeval begin;
   struct timeval end;
   struct timeval last_flush;
   uint32_t pkts_from_begin = 0;
   double time_per_pkt = 1000000.0 / fps; // [micro seconds]

   // Rate limiting algorithm from https://github.com/CESNET/ipfixcol2/blob/master/src/tools/ipfixsend/sender.c#L98
   gettimeofday(&begin, NULL);
   last_flush = begin;
   while (1) {
      gettimeofday(&end, NULL);

      Flow *flow = static_cast<Flow *>(ipx_ring_pop(queue));
      if (!flow) {
         if (end.tv_sec - last_flush.tv_sec > 1) {
            last_flush = end;
            exp->flush();
         }
         if (terminate_export && !ipx_ring_cnt(queue)) {
            break;
         }
         continue;
      }

      stats.biflows++;
      stats.bytes += flow->src_octet_total_length + flow->dst_octet_total_length;
      stats.packets += flow->src_pkt_total_cnt + flow->dst_pkt_total_cnt;
      exp->export_flow(*flow);

      pkts_from_begin++;
      if (fps == 0) {
         // Limit for packets/s is not enabled
         continue;
      }

      // Calculate expected time of sending next packet
      long elapsed = timeval_diff(&begin, &end);
      if (elapsed < 0) {
         // Should be never negative. Just for sure...
         elapsed = pkts_from_begin * time_per_pkt;
      }

      long next_start = pkts_from_begin * time_per_pkt;
      long diff = next_start - elapsed;

      if (diff >= MICRO_SEC) {
         diff = MICRO_SEC - 1;
      }

      // Sleep
      if (diff > 0) {
         sleep_time.tv_nsec = diff * 1000L;
         nanosleep(&sleep_time, NULL);
      }

      if (pkts_from_begin >= fps) {
         // Restart counter
         gettimeofday(&begin, NULL);
         pkts_from_begin = 0;
      }
   }
   stats.dropped = exp->flows_dropped;
   threadOutput->set_value(stats);
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
inline int error(const string &e)
{
   cerr << "Error: " << e << endl;
   return EXIT_FAILURE;
}

/**
 * \brief Signal handler function.
 * \param [in] sig Signal number.
 */
void signal_handler(int sig)
{
#ifdef HAVE_LIBUNWIND
   if (sig == SIGSEGV) {
      st_dump(STDERR_FILENO, sig);
      abort();
   }
#endif
   stop = 1;
}

#ifndef WITH_NEMEA
typedef struct module_param_s {
   char   short_opt;
   char  *long_opt;
   char  *description;
   int param_required_argument;
   char  *argument_type;
} module_param_t;

#define GEN_LONG_OPT_STRUCT_LINE(p_short_opt, p_long_opt, p_description, p_required_argument, p_argument_type) \
   {p_long_opt, p_required_argument, 0, p_short_opt},

#define GEN_LONG_OPT_STRUCT(PARAMS) \
   static struct option long_options[] __attribute__((used)) = { \
      PARAMS(GEN_LONG_OPT_STRUCT_LINE) \
      {0, 0, 0, 0} \
   }

#define FILL_PARAMS(p_short_opt, p_long_opt, p_description, p_required_argument, p_argument_type) \
   module_getopt_string[optidx++] = p_short_opt; \
   if (p_required_argument == required_argument) {module_getopt_string[optidx++] = ':';}
#endif

struct WorkPipeline {
   struct {
      PacketReceiver *plugin;
      std::thread *thread;
      std::promise<InputStats> *promise;
   } input;
   struct {
      FlowCache *plugin;
      std::thread *thread;
      std::promise<StorageStats> *promise;
      std::vector<FlowCachePlugin *> plugins;
   } storage;
   ipx_ring_t *queue;
};

struct ExporterWorker {
   FlowExporter *plugin;
   std::thread *thread;
   std::promise<OutputStats> *promise;
   ipx_ring_t *queue;
};

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
   options.basic_ifc_num = 0;
   options.snaplen = 0;
   options.eof = true;
   options.flow_cache_qsize = 16536;
   options.input_qsize = 64;
   options.input_pktblock_size = 32;
   options.fps = 0;

#ifdef WITH_NEMEA
   bool odid = false;
#else
   GEN_LONG_OPT_STRUCT(MODULE_PARAMS);
#endif

   bool export_unirec = false;
   bool export_ipfix = false;
   bool help = false;
   bool udp = false;
   int ifc_cnt = 0;
   int verbose = -1;
   uint64_t link = 1;
   uint64_t pkt_limit = 0;
   uint8_t dir = 0;
   std::string host = "";
   std::string port = "";
   std::string filter = "";
   uint16_t mtu = PACKET_DATA_SIZE;

   for (int i = 0; i < argc; i++) {
      if (!strcmp(argv[i], "-i")) {
         export_unirec = true;
      } else if (!strcmp(argv[i], "-x") || !strcmp(argv[i], "--ipfix")) {
         export_ipfix = true;
      } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
         help = true;
      } else if (!strcmp(argv[i], "-V") || !strcmp(argv[i], "--version")) {
         help = true;
         printf("%s (%s) %s\n", PACKAGE, PACKAGE_NAME, VERSION);
         puts ("");
         return 0;

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

#ifdef WITH_NEMEA
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
#else
   char module_getopt_string[100];
   int optidx = 0;
   MODULE_PARAMS(FILL_PARAMS)
#endif

   if ((export_unirec && !export_ipfix) || help) {
#ifdef WITH_NEMEA
      /* TRAP initialization */
      ifc_cnt = count_trap_interfaces(argc, argv);
      module_info->num_ifc_out = ifc_cnt;
      TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
#else
      puts("ipfixprobe version " VERSION);
      puts("ipfixprobe is an IPFIX flow exporter support supporting various custom IPFIX elements.");
      puts("");
      puts("Usage: ipfixprobe [-I interface] -x host:port [-u] [-p " SUPPORTED_PLUGINS_LIST "] [-r file]");
      puts("");

      MODULE_PARAMS(PRINT_HELP_PARAM)

#endif
   } else if (verbose >= 0) {
      for (int i = verbose; i + 1 < argc; i++) {
         argv[i] = argv[i + 1];
      }
      argc--;
   }

   if (export_unirec && export_ipfix) {
#ifdef WITH_NEMEA
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
#endif
      return error("Cannot export to IPFIX and Unirec at the same time.");
   } else if (!export_unirec && !export_ipfix && !help) {
#ifdef WITH_NEMEA
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
#endif
      return error("Specify exporter output Unirec (-i) or IPFIX (-x/--ipfix).");
   }

   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
#ifdef HAVE_LIBUNWIND
   signal(SIGSEGV, signal_handler);
#endif
   signal(SIGPIPE, SIG_IGN);

   signed char opt;
   while ((opt = getopt_long(argc, argv, module_getopt_string, long_options, NULL)) != -1) {
      switch (opt) {
      case 'p':
         {
            options.basic_ifc_num = -1;
            int ret = parse_plugin_settings(string(optarg), plugin_wrapper.plugins, options);
            if (ret < 0) {
#ifdef WITH_NEMEA
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -p");
            }
            if (ifc_cnt && ret != ifc_cnt) {
#ifdef WITH_NEMEA
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Number of output ifc interfaces does not correspond number of items in -p parameter.");
            }
         }
         break;
      case 'c':
         {
            if (!str_to_uint64(optarg, pkt_limit)) {
#ifdef WITH_NEMEA
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -c");
            }
         }
         break;
      case 'I':
         options.interface.push_back(string(optarg));
         break;
      case 't':
         {
            if (!strcmp(optarg, "default")) {
               break;
            }

            char *check;
            check = strchr(optarg, ':');
            if (check == NULL) {
#ifdef WITH_NEMEA
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -t");
            }

            *check = '\0';
            double tmp1, tmp2;
            if (!str_to_double(optarg, tmp1) || !str_to_double(check + 1, tmp2) || tmp1 < 0 || tmp2 < 0) {
#ifdef WITH_NEMEA
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
         options.pcap_file.push_back(string(optarg));
         break;
      case 'n':
         options.eof = false;
         break;
      case 'l':
         if (!str_to_uint32(optarg, options.snaplen)) {
#ifdef WITH_NEMEA
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
#ifdef WITH_NEMEA
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
#ifdef WITH_NEMEA
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
#ifdef WITH_NEMEA
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
#endif
            return error("Invalid argument for option -L");
         }
         break;
      case 'D':
         if (!str_to_uint8(optarg, dir)) {
#ifdef WITH_NEMEA
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
#ifdef WITH_NEMEA
         odid = true;
#endif
         break;
      case 'x':
         {
            host = optarg;
            size_t tmp = host.find_last_of(":");
            if (tmp == string::npos) {
#ifdef WITH_NEMEA
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
#ifdef WITH_NEMEA
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
      case 'q':
         {
            if (!strcmp(optarg, "default")) {
               break;
            }
            uint32_t tmp;
            if (!str_to_uint32(optarg, tmp) || tmp == 0) {
#ifdef WITH_NEMEA
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -q");
            }
            options.input_qsize = tmp;
         }
         break;
      case 'Q':
         {
            if (!strcmp(optarg, "default")) {
               break;
            }
            uint32_t tmp;
            if (!str_to_uint32(optarg, tmp) || tmp == 0) {
#ifdef WITH_NEMEA
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -Q");
            }
            options.flow_cache_qsize = tmp;
         }
         break;
      case 'e':
            if (!str_to_uint32(optarg, options.fps)) {
#ifdef WITH_NEMEA
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -e");
            }
            break;
      case 'm':
            if (!str_to_uint16(optarg, mtu)) {
#ifdef WITH_NEMEA
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
#endif
               return error("Invalid argument for option -m");
            }
            break;
      default:
#ifdef WITH_NEMEA
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
#endif
         if (!help) {
#ifndef HAVE_NDP
            if (optopt == 'I') {
               PcapReader::print_interfaces();
               return 1;
            }
#endif
            return error("Invalid arguments");
         } else {
            return 0;
         }
      }
   }

#ifdef WITH_NEMEA
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
#endif

   if (options.interface.size() && options.pcap_file.size()) {
#ifdef WITH_NEMEA
      TRAP_DEFAULT_FINALIZATION();
#endif
      return error("Cannot capture from file and from interface at the same time.");
   } else if (options.interface.size() == 0 && options.pcap_file.size() == 0) {
#ifdef WITH_NEMEA
      TRAP_DEFAULT_FINALIZATION();
#endif
      return error("Specify capture interface (-I) or file for reading (-r). ");
   }

   if (options.snaplen == 0) { /* Check if user specified snapshot length. */
      options.snaplen = MAXPCKTSIZE;
   }

   FlowExporter *exporter;
   if (export_unirec) {
#ifdef WITH_NEMEA
      if (options.interface.size()) {
         for (int i = 0; i < ifc_cnt; i++) {
            trap_ifcctl(TRAPIFC_OUTPUT, i, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);
         }
      }
      UnirecExporter *ipxe = new UnirecExporter(options.eof);
      if (ipxe->init(plugin_wrapper.plugins, ifc_cnt, options.basic_ifc_num, link, dir, odid) != 0) {
         TRAP_DEFAULT_FINALIZATION();
         return error("Unable to initialize UnirecExporter.");
      }
      exporter = ipxe;
#endif
   } else {
      IPFIXExporter *ipxe = new IPFIXExporter();
      if (ipxe->init(plugin_wrapper.plugins, options.basic_ifc_num, link, host, port, udp, mtu, (verbose >= 0), dir) != 0) {
#ifdef WITH_NEMEA
         TRAP_DEFAULT_FINALIZATION();
#endif
         return error("Unable to initialize IPFIXExporter.");
      }
      exporter = ipxe;
   }
   ipx_ring_t *export_queue = ipx_ring_init(options.flow_cache_qsize, 1);
   if (export_queue == NULL) {
      return error("Unable to initialize ring buffer.");
   }

   if (!options.print_stats) {
      plugin_wrapper.plugins.push_back(new StatsPlugin(options.cache_stats_interval, cout));
   }

   std::vector<WorkPipeline> pipelines;
   std::vector<ExporterWorker> exporters;
   std::vector<std::future<InputStats>> inputFutures;
   std::vector<std::future<StorageStats>> storageFutures;
   std::vector<std::future<OutputStats>> outputFutures;

   std::promise<OutputStats> *exporter_stats = new std::promise<OutputStats>();
   ExporterWorker tmp = {
      exporter,
      new std::thread(export_thread, exporter, export_queue, exporter_stats, options.fps),
      exporter_stats,
      export_queue
   };
   exporters.push_back(tmp);
   outputFutures.push_back(exporter_stats->get_future());

   size_t worker_cnt = options.interface.size() ? options.interface.size() : options.pcap_file.size();
   size_t blocks_cnt = (options.input_qsize + 1) * worker_cnt;
   size_t pkts_cnt = blocks_cnt * options.input_pktblock_size;
   size_t pkt_data_cnt = pkts_cnt * (MAXPCKTSIZE + 1);
   int ret = EXIT_SUCCESS;
   bool print_stats = false;
   bool livecapture = options.interface.size();

   PacketBlock *blocks = new PacketBlock[blocks_cnt];
   Packet *pkts = new Packet[pkts_cnt];
   char *pkt_data = new char[pkt_data_cnt];

   for (unsigned i = 0; i < blocks_cnt; i++) {
      blocks[i].pkts = pkts + i * options.input_pktblock_size;
      blocks[i].cnt = 0;
      blocks[i].size = options.input_pktblock_size;
      for (unsigned j = 0; j < options.input_pktblock_size; j++) {
         blocks[i].pkts[j].packet = (char *) (pkt_data + (MAXPCKTSIZE + 1) * (j + i * options.input_pktblock_size));
      }
   }

   for (unsigned i = 0; i < worker_cnt; i++) {
#ifdef HAVE_NDP
      PacketReceiver *packetloader = new NdpPacketReader(options);
#else /* HAVE_NDP */
      PacketReceiver *packetloader = new PcapReader(options);
#endif /* HAVE_NDP */

      if (options.interface.size() == 0) {
         if (packetloader->open_file(options.pcap_file[i], true) != 0) {
            error("Can't open input file: " + options.pcap_file[i]);
            delete packetloader;
            ret = EXIT_FAILURE;
            goto EXIT;
         }
      } else {
         if (packetloader->init_interface(options.interface[i], options.snaplen, true) != 0) {
            error("Unable to initialize network interface: " + packetloader->error_msg);
            delete packetloader;
            ret = EXIT_FAILURE;
            goto EXIT;
         }
      }
      if (filter != "") {
         if (packetloader->set_filter(filter) != 0) {
            error(packetloader->error_msg);
            delete packetloader;
            ret = EXIT_FAILURE;
            goto EXIT;
         }
      }

      FlowCache *flowcache = new NHTFlowCache(options);
      flowcache->set_queue(export_queue);

      std::vector<FlowCachePlugin *> plugins;
      for (unsigned int i = 0; i < plugin_wrapper.plugins.size(); i++) {
         FlowCachePlugin *plugin = plugin_wrapper.plugins[i]->copy();
         plugins.push_back(plugin);
         flowcache->add_plugin(plugin);
      }
      flowcache->init();

      ipx_ring_t *input_queue = ipx_ring_init(options.input_qsize, 0);
      if (export_queue == NULL) {
         error("Unable to initialize ring buffer.");
         delete packetloader;
         delete flowcache;
         ret = EXIT_FAILURE;
         goto EXIT;
      }

      std::promise<InputStats> *input_stats = new std::promise<InputStats>();
      std::promise<StorageStats> *storage_stats = new std::promise<StorageStats>();

      inputFutures.push_back(input_stats->get_future());
      storageFutures.push_back(storage_stats->get_future());

      WorkPipeline tmp = {
         {
            packetloader,
            new std::thread(input_thread, packetloader, &blocks[i * (options.input_qsize + 1)], options.input_qsize + 1, pkt_limit, input_queue, input_stats),
            input_stats,
         },
         {
            flowcache,
            new std::thread(storage_thread, flowcache, input_queue, storage_stats),
            storage_stats,
            plugins
         },
         input_queue
      };
      pipelines.push_back(tmp);
   }

   print_stats = true;
   while (!stop) {
      bool alldone = true;
      for (unsigned i = 0; i < inputFutures.size(); i++) {
         std::future_status status = inputFutures[i].wait_for(std::chrono::seconds(0));
         if (status == std::future_status::ready && livecapture) {
            stop = 1;
            break;
         } else if (status != std::future_status::ready) {
            alldone = false;
         }
      }
      if (!livecapture && alldone) {
         stop = 1;
      }
      usleep(1000);
   }

EXIT:
   terminate_input = 1;
   for (unsigned i = 0; i < pipelines.size(); i++) {
      pipelines[i].input.thread->join();
      pipelines[i].input.plugin->close();
      delete pipelines[i].input.plugin;
      delete pipelines[i].input.thread;
      delete pipelines[i].input.promise;
   }

   if (print_stats) {
      std::cout << "Input stats:" << std::endl <<
         std::setw(3) << "#" <<
         std::setw(10) << "packets" <<
         std::setw(10) << "parsed" <<
         std::setw(16) << "bytes" <<
         std::setw(10) << "qtime" <<
         std::setw(7)  << "status" << std::endl;

      for (unsigned i = 0; i < inputFutures.size(); i++) {
         InputStats input = inputFutures[i].get();
         std::string status = "ok";
         if (input.error) {
            ret = EXIT_FAILURE;
            status = input.msg;
         }
         std::cout <<
            std::setw(3) << i << " " <<
            std::setw(9) << input.packets << " " <<
            std::setw(9) << input.parsed << " " <<
            std::setw(15) << input.bytes << " " <<
            std::setw(9) << input.qtime << " " <<
            std::setw(6) << status << std::endl;
      }
   }

   terminate_storage = 1;
   for (unsigned i = 0; i < pipelines.size(); i++) {
      pipelines[i].storage.thread->join();
      pipelines[i].storage.plugin->finish();
      for (unsigned j = 0; j < pipelines[i].storage.plugins.size(); j++) {
         delete pipelines[i].storage.plugins[j];
      }
   }

   terminate_export = 1;
   for (unsigned i = 0; i < exporters.size(); i++) {
      exporters[i].thread->join();
      delete exporters[i].plugin;
      delete exporters[i].thread;
      delete exporters[i].promise;
      ipx_ring_destroy(exporters[i].queue);
   }

   if (print_stats) {
      std::cout << "Output stats:" << std::endl <<
         std::setw(3) << "#" <<
         std::setw(10) << "biflows" <<
         std::setw(10) << "packets" <<
         std::setw(16) << "bytes" <<
         std::setw(10) << "dropped" << std::endl;

      for (unsigned i = 0; i < outputFutures.size(); i++) {
         OutputStats output = outputFutures[i].get();
         std::cout <<
            std::setw(3) << i << " " <<
            std::setw(9) << output.biflows << " " <<
            std::setw(9) << output.packets << " " <<
            std::setw(15) << output.bytes << " " <<
            std::setw(9) << output.dropped << std::endl;
      }
   }

   for (unsigned i = 0; i < pipelines.size(); i++) {
      delete pipelines[i].storage.plugin;
      delete pipelines[i].storage.thread;
      delete pipelines[i].storage.promise;
      ipx_ring_destroy(pipelines[i].queue);
   }
   delete [] pkts;
   delete [] blocks;
   delete [] pkt_data;

#ifdef WITH_NEMEA
   TRAP_DEFAULT_FINALIZATION();
#endif

   return ret;
}
