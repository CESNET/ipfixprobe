/**
 * \file main.c
 * \date 2019
 * \author Jiri Havranek <havranek@cesnet.cz>
 */
/*
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
*/

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>

#include <pcap.h>

#include "cache.h"
#include "ipfix.h"
#include "parser.h"
#include "plugin.h"
#include "types.h"

#ifndef DEFAULT_FLOWCACHE_SIZE
#define DEFAULT_FLOWCACHE_SIZE (1 << 17) // 2 ^ 17
#endif

#define MODULE_OPTIONS(OPTION) \
   OPTION("h", "help", "Print this message.", NO_ARGUMENT) \
   OPTION("v", "verbose", "Set verbose mode.", NO_ARGUMENT) \
   OPTION("i", "interface", "Read packets from network interface.", REQUIRED_ARGUMENT) \
   OPTION("c", "count", "End after number of packets are processed.", REQUIRED_ARGUMENT) \
   OPTION("r", "pcap", "Read packets from pcap file.", REQUIRED_ARGUMENT) \
   OPTION("f", "filter", "String containing filter expression to filter packets. See `man pcap-filter`.", REQUIRED_ARGUMENT) \
   OPTION("s", "size", "Cache size exponent n. Accept values 1-31 (cache size=2^n), default is 17.", REQUIRED_ARGUMENT) \
   OPTION("l", "line", "Cache line size. Must be power of two.", REQUIRED_ARGUMENT) \
   OPTION("t", "timeout", "Active and inactive timeouts in seconds. Format 'active:inactive'.", REQUIRED_ARGUMENT) \
   OPTION("o", "odid", "Set observation domain ID.", REQUIRED_ARGUMENT) \
   OPTION("x", "ipfix", "Specify IPFIX exporter address and port. Format: `IPv4:PORT` and `[IPv6]:PORT`", REQUIRED_ARGUMENT) \
   OPTION("u", "udp", "Use UDP instead of default TCP protocol for collector connection.", NO_ARGUMENT) \
   OPTION("p", "plugins", "Activate parsing plugins. Specify list of names separated by comma. Available plugins: " PLUGINS_AVAILABLE, REQUIRED_ARGUMENT) \

/* Create help string for printf from module options. */
#define NO_ARGUMENT        " "
#define REQUIRED_ARGUMENT  " <ARG>"
#define OPTIONAL_ARGUMENT  " [<ARG>]"
#define CREATE_PRINTF_STRING(SHORT, LONG, DESCRIPTION, ARGUMENT) \
   "   -" SHORT "  --%-*s " DESCRIPTION "\n"

/* Count maximum length of long help string (long option string + it's argument string). */
#define COUNT_MAX_LONG_HELP_STRING_LENGTH(SHORT, LONG, DESCRIPTION, ARGUMENT) \
   if (max_option_len < strlen(LONG) + strlen(ARGUMENT)) { \
      max_option_len = strlen(LONG) + strlen(ARGUMENT); \
   }

/* Add args to printf function call. */
#define CREATE_PRINTF_ARGS(SHORT, LONG, DESCRIPTION, ARGUMENT) \
   , max_option_len, LONG ARGUMENT

/**
 * \brief Print help to stdout.
 * \param [in] program Program name.
 */
void print_help(const char *program)
{
   int max_option_len = 1;
   MODULE_OPTIONS(COUNT_MAX_LONG_HELP_STRING_LENGTH);
   printf("Usage: %s [OPTIONS]\nOPTIONS:\n"
           MODULE_OPTIONS(CREATE_PRINTF_STRING),
           program MODULE_OPTIONS(CREATE_PRINTF_ARGS));
}
#undef NO_ARGUMENT
#undef REQUIRED_ARGUMENT
#undef OPTIONAL_ARGUMENT

/* Create short option for getopt from module options.*/
#define NO_ARGUMENT        ""
#define REQUIRED_ARGUMENT  ":"
#define OPTIONAL_ARGUMENT  "::"
#define GETOPT_CREATE_SHORT_STRING(SHORT, LONG, DESCRIPTION, ARGUMENT) \
   SHORT ARGUMENT
const char *short_options = MODULE_OPTIONS(GETOPT_CREATE_SHORT_STRING);
#undef NO_ARGUMENT
#undef REQUIRED_ARGUMENT
#undef OPTIONAL_ARGUMENT

/* Used to create long options for getopt from module options. */
#define NO_ARGUMENT 0
#define REQUIRED_ARGUMENT 1
#define OPTIONAL_ARGUMENT 2
#define MODULE_OPTIONS_COUNT(SHORT, LONG, DESCRIPTION, ARGUMENT) 1 +
#define CREATE_LONG_OPTIONS(SHORT, LONG, DESCRIPTION, ARGUMENT) \
   long_options[i].name = LONG; \
   long_options[i].has_arg = ARGUMENT; \
   long_options[i].flag = NULL; \
   long_options[i++].val = SHORT[0];
#define NULL_OPTION(FUNC) \
   FUNC("", NULL, NULL, 0)

/**
 * \brief Create long options for getopt.
 * \return Structure containing created options or NULL on error.
 */
struct option *long_options_init()
{
   int i = 0;
   struct option *long_options = malloc((MODULE_OPTIONS(MODULE_OPTIONS_COUNT) 1) * sizeof(*long_options));

   if (long_options == NULL) {
      return NULL;
   }

   MODULE_OPTIONS(CREATE_LONG_OPTIONS);
   NULL_OPTION(CREATE_LONG_OPTIONS);

   return long_options;
}

/**
 * \brief Convert string to uint32_t.
 * \param [in] str Input trimmed string.
 * \param [out] value Output value.
 * \return 0 on success, non zero otherwise.
 */
int str_to_uint32(const char *str, uint32_t *value)
{
   unsigned long long int tmp;
   char *check;

   errno = 0;
   tmp = strtoull(str, &check, 0);

   if (errno == EINVAL || errno == ERANGE ||
       str[0] == '-' || str[0] == 0 || *check != 0 ||
       tmp > UINT32_MAX) {
      return 1;
   }
   *value = tmp;

   return 0;
}

/**
 * \brief Function will remove whitespaces from begin and end of string.
 * \param [in,out] str Pointer to string to be trimmed.
 */
void trim_str(char *str)
{
   char *begin = str;
   char *end;

   if (str == NULL) {
      return;
   }

   /* Trim begin of string. */
   for (; isspace(*begin); begin++) {
   }

   end = begin + strlen(begin) - 1;

   /* Trim end of string. */
   for (; end > begin && isspace(*end); end--) {
      *end = 0;
   }

   /* Move string. */
   for (; begin <= end; begin++, str++) {
      *str = *begin;
   }
   *str = 0;
}

static int stop = 0;
void signal_handler(int sig)
{
   stop = 1;
}

int main(int argc, char *argv[])
{
   int ret;
   int status = 0;
   uint32_t packet_limit = 0;
   uint64_t total_bytes = 0;
   uint64_t total_packets = 0;
   const char *pcap_uri = NULL;
   const char *interface = NULL;
   const char *plugins = NULL;

   struct fpp_parser_s parser;
   struct packet_hdr_s *parsed_hdr = NULL;

   struct flowcache_s cache;
   uint32_t cache_size  = DEFAULT_FLOWCACHE_SIZE;
   uint32_t cache_line_size = 16;
   uint32_t timeout_active = 300;
   uint32_t timeout_inactive = 30;

   struct ipfix_s ipfix;
   uint32_t odid = 1;
   char *host = "";
   char *port = "";
   int udp = 0;
   int verbose = 0;
   uint8_t dir = 1;
   int export_basic = 1;

   int snaplen = 1500;
   int timeout = 1000;

   char errbuf[PCAP_ERRBUF_SIZE];
   const u_char *packet_raw = NULL;
   struct pcap_pkthdr *hdr = NULL;
   pcap_t *handle = NULL;
   struct bpf_program filter;
   char *filter_str = NULL;

   struct option *long_options = long_options_init();
   memset(&cache, 0, sizeof(cache));
   ipfix_prepare(&ipfix);
   fpp_init(&parser);
   errbuf[0] = 0;

   if (long_options == NULL) {
      fprintf(stderr, "Error: not enough memory for getopt long options allocation\n");
      return 1;
   }

   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   signal(SIGPIPE, SIG_IGN);

   /* Process module parameters. */
   while ((ret = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
      switch (ret) {
         case 'h':
            print_help(argv[0]);
            free(long_options);
            return 0;
         case 'v':
            verbose++;
            break;
         case 'c':
            {
               trim_str(optarg);
               uint32_t val;
               if (str_to_uint32(optarg, &val)) {
                  fprintf(stderr, "Error: invalid argument for option -c\n");
                  free(long_options);
                  return 1;
               }
               packet_limit = val;
            }
            break;
         case 'i':
            interface = optarg;
            break;
         case 'r':
            pcap_uri = optarg;
            break;
         case 'f':
            filter_str = optarg;
            break;
         case 's':
            {
               trim_str(optarg);
               uint32_t val;
               if (str_to_uint32(optarg, &val)) {
                  fprintf(stderr, "Error: invalid argument for option -s\n");
                  free(long_options);
                  return 1;
               }
               cache_size = 1 << val;
            }
            break;
         case 'l':
            {
               trim_str(optarg);
               uint32_t val;
               if (str_to_uint32(optarg, &val)) {
                  fprintf(stderr, "Error: invalid argument for option -l\n");
                  free(long_options);
                  return 1;
               }
               cache_line_size = val;

               uint32_t tmp = cache_line_size;
               while (tmp) {
                  if ((tmp & 1) && (tmp >> 1)) {
                     fprintf(stderr, "Error: size of cache line size must be power of 2\n");
                     free(long_options);
                     return 1;
                  }
                  tmp >>= 1;
               }
            }
            break;
         case 't':
            {
               trim_str(optarg);
               if (!strcmp(optarg, "default")) {
                  break;
               }

               char *check;
               check = strchr(optarg, ':');
               if (check == NULL) {
                  fprintf(stderr, "Error: invalid argument for option -t\n");
                  free(long_options);
                  return 1;
               }

               *check = '\0';
               trim_str(optarg);
               trim_str(check + 1);
               if (str_to_uint32(optarg, &timeout_active) || str_to_uint32(check + 1, &timeout_inactive)) {
                  fprintf(stderr, "Error: invalid argument for option -t\n");
                  free(long_options);
                  return 1;
               }
            }
            break;
         case 'o':
            if (str_to_uint32(optarg, &odid)) {
               fprintf(stderr, "Error: invalid argument for option -o\n");
               free(long_options);
               return 1;
            }
            break;
         case 'x':
            {
               host = optarg;
               char *c;
               for (c = host + strlen(host); c > host; c--) {
                  if (*c == ':') {
                     break;
                  }
               }
               if (c == host) {
                  fprintf(stderr, "Error: invalid argument for option -x\n");
                  free(long_options);
                  return 1;
               }
               port = c + 1;
               *c = 0;
               trim_str(host);
               trim_str(port);

               size_t host_len = strlen(host);
               size_t port_len = strlen(port);

               if (host_len == 0 || port_len == 0) {
                  fprintf(stderr, "Error: invalid argument for option -x\n");
                  free(long_options);
                  return 1;
               }
               if (host[0] == '[' && host[host_len - 1] == ']') {
                  host[host_len - 1] = 0;
                  host++;
               }
            }
            break;
         case 'u':
            udp = 1;
            break;
         case 'p':
            plugins = optarg;
            if (plugins != NULL && !check_plugins_string(plugins)) {
               fprintf(stderr, "Error: invalid argument for option -p\n");
               free(long_options);
               return 1;
            }
            break;
         default:
            free(long_options);
            return 1;
      }
   }

   free(long_options);

   if (interface != NULL && pcap_uri != NULL) {
      fprintf(stderr, "Error: unable to read from interface and pcap at the same time\n");
      return 1;
   } else if (interface != NULL) {
      /* Open network interface for reading. */
      handle = pcap_open_live(interface, snaplen, 1, timeout, errbuf);
      if (handle == NULL) {
         fprintf(stderr, "Error: unable to open capture interface: %s\n", errbuf);
         status = 1;
         goto EXIT;
      }
      if (errbuf[0] != 0) {
         fprintf(stderr, "%s\n", errbuf); // Print warning.
      }

      if (pcap_datalink(handle) != DLT_EN10MB) {
         fprintf(stderr, "Error: unsupported data link type\n");
         status = 1;
         goto EXIT;
      }
   } else if (pcap_uri != NULL) {
      /* Open pcap file. */
      handle = pcap_open_offline(pcap_uri, errbuf);
      if (handle == NULL) {
         fprintf(stderr, "Error: unable to open PCAP file: %s\n", errbuf);
         status = 1;
         goto EXIT;
      }
   } else {
      fprintf(stderr, "Error: specify input, -r or -i\n");
      status = 1;
      goto EXIT;
   }

   /* Compile filter expression if specified. */
   if (filter_str != NULL) {
      if (pcap_compile(handle, &filter, filter_str, 0, PCAP_NETMASK_UNKNOWN) == -1) {
         fprintf(stderr, "Error: could not parse filter '%s': %s\n", filter_str, pcap_geterr(handle));
         status = 1;
         goto EXIT;
      }
      if (pcap_setfilter(handle, &filter) == -1) {
         fprintf(stderr, "Error: could not install filter '%s': %s\n", filter_str, pcap_geterr(handle));
         pcap_freecode(&filter);
         status = 1;
         goto EXIT;
      }
      pcap_freecode(&filter);
   }

   if (*host == 0) {
      fprintf(stderr, "Error: specify exporter address and port -x\n");
      status = 1;
      goto EXIT;
   }

   if (plugins != NULL) {
      export_basic = (strstr(plugins, "basic") != NULL ? 1 : 0);
   }

   ipfix_init(&ipfix, odid, host, port, udp, verbose, dir, export_basic);
   if (!cache_init(&cache, cache_size, cache_line_size, timeout_active, timeout_inactive, &ipfix, plugins)) {
      fprintf(stderr, "Error: unable to initialize cache\n");
      status = 1;
      goto EXIT;
   }

   /* Packet reading loop. */
   while (!stop && (ret = pcap_next_ex(handle, &hdr, &packet_raw))) {
      if (ret == 0) {
         // Timeout occured
         cache_export_expired(&cache, time(NULL));
         continue;
      } else if (ret == -1) {
         fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
         status = 1;
         goto EXIT;
      } else if (ret == -2 || (packet_limit && total_packets >= packet_limit)) {
         break;
      }
      total_packets++;
      total_bytes += hdr->caplen;

      if (fpp_parse_packet(&parser, packet_raw, hdr->caplen, &parsed_hdr) != NoError) {
         fpp_free(&parser, parsed_hdr);
         continue;
      }

      cache_add_packet(&cache, parsed_hdr, hdr->ts, 0, packet_raw, hdr->caplen);
      fpp_free(&parser, parsed_hdr);
   }

   cache_export_all(&cache);

   printf("%s:\n", pcap_uri);
   printf("   %" PRIu64 " packets read (%" PRIu64 " bytes)\n", total_packets, total_bytes);
   printf("   %" PRIu64 " packets processed in cache\n", cache.packets_total);
   printf("   %" PRIu64 " flow records created\n", cache.flows_total);

EXIT:
   fpp_clear(&parser);
   cache_clear(&cache);
   ipfix_shutdown(&ipfix);
   /* Cleanup. */
   if (handle != NULL) {
      pcap_close(handle);
   }
   return status;
}
