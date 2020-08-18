/**
 * \file ssdpplugin.cpp
 * \brief Plugin for parsing ssdp traffic.
 * \author Ondrej Sedlacek xsedla1o@stud.fit.vutbr.cz
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
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
 * This software is provided as is'', and any express or implied
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

#include <iostream>

#include "ssdpplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "ipfix-elements.h"

using namespace std;

// #define DEBUG_SSDP

// Print debug message if debugging is allowed.
#ifdef DEBUG_SSDP
#define SSDP_DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define SSDP_DEBUG_MSG(format, ...)
#endif

#define SSDP_UNIREC_TEMPLATE "SSDP_LOCATION_PORT,SSDP_NT,SSDP_SERVER,SSDP_ST,SSDP_USER_AGENT"

UR_FIELDS (
   uint16 SSDP_LOCATION_PORT,
   string SSDP_NT,
   string SSDP_SERVER,
   string SSDP_ST,
   string SSDP_USER_AGENT
)

enum header_types {
   LOCATION,
   NT,
   ST,
   SERVER,
   USER_AGENT,
   NONE
};

const char *headers[] = {
   "location",
   "nt",
   "st",
   "server",
   "user-agent"
};

SSDPPlugin::SSDPPlugin(const options_t &module_options)
{
   record = NULL;
   print_stats = module_options.print_stats;
   notifies = 0;
   searches = 0;
   total = 0;
}

SSDPPlugin::SSDPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   record = NULL;
   print_stats = module_options.print_stats;
   notifies = 0;
   searches = 0;
   total = 0;
}

int SSDPPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (pkt.dst_port == 1900) {
      record = new RecordExtSSDP();
      rec.addExtension(record);
      record = NULL;

      parse_ssdp_message(rec, pkt);
   }
   return 0;
}

int SSDPPlugin::pre_update(Flow &rec, Packet &pkt)
{
   if (pkt.dst_port == 1900) {
      parse_ssdp_message(rec, pkt);
   }
   return 0;
}

void SSDPPlugin::finish()
{
   if (print_stats) {
      cout << "SSDP plugin stats:" << endl;
      cout << "   Parsed SSDP M-Searches: " << searches << endl;
      cout << "   Parsed SSDP Notifies: " << notifies << endl;
      cout << "   Total SSDP packets processed: " << total << endl;
   }
}

/**
 * \brief Parses port from location header message string.
 * 
 * \param [in, out] data Pointer to SSDP data.
 * \param [in] ip_version IP version of the Location url being parsed.
 * \return Parsed port number on success, 0 otherwise.
 */
uint16_t SSDPPlugin::parse_loc_port(char *data, uint8_t ip_version)
{
   uint16_t port;
   char *end_ptr = NULL;

   if (ip_version == 6) {
      data = strchr(data, ']');
   } else {
      data = strchr(data, '.');
   }
   data = strchr(data, ':');

   if (data) {
      data++;
   }

   port = strtol(data, &end_ptr, 0);
   if (data != end_ptr) {
      return port;
   } else {
      return 0;
   }
}

/**
 * \brief Checks for given header string in data
 * 
 * \param [in, out] data Pointer to pointer to SSDP data.
 * \param [in] header String containing the desired header.
 * \param [in] len Lenght of the desired header.
 * \return True if the header is found, otherwise false.
 */
bool SSDPPlugin::get_header_val(char **data, const char *header, const int len)
{
   if (strncasecmp(*data, header, len) == 0 && (*data)[len] == ':') {
      (*data) += len + 1;
      while (isspace(**data)) {
         (*data)++;
      };
      return true;
   }
   return false;
}

/**
 * \brief Parses SSDP payload based on configuration in conf struct.
 * 
 * \param [in] data Pointer to pointer to SSDP data.
 * \param [in] conf Struct containing parser configuration.
 */
void SSDPPlugin::parse_headers(char *data, header_parser_conf conf)
{
   char *ptr = data;
   char *old_ptr = ptr;

   while (*ptr != '\0') {
      if (*ptr == '\n' && *(ptr - 1) == '\r') {
         *(ptr - 1) = '\0';
         for (unsigned j = 0, i = 0; j < conf.select_cnt; j++) {
            i = conf.select[j];
            if (get_header_val(&old_ptr, conf.headers[i], strlen(conf.headers[i]))) {
               switch ((header_types) i) {
               case ST:
                  if (get_header_val(&old_ptr, "urn", strlen("urn"))) {
                     SSDP_DEBUG_MSG("%s\n", old_ptr);
                     append_value(conf.ext->st, SSDP_URN_LEN, old_ptr);
                  }
                  break;
               case NT:
                  if (get_header_val(&old_ptr, "urn", strlen("urn"))) {
                     SSDP_DEBUG_MSG("%s\n", old_ptr);
                     append_value(conf.ext->nt, SSDP_URN_LEN, old_ptr);
                  }
                  break;
               case LOCATION:
                  {
                     uint16_t port = parse_loc_port(old_ptr, conf.ip_version);

                     if (port > 0) {
                        SSDP_DEBUG_MSG("%d <- %d\n", conf.ext->port, port);
                        conf.ext->port = port;
                     }
                     break;
                  }
               case USER_AGENT:
                  SSDP_DEBUG_MSG("%s\n", old_ptr);
                  append_value(conf.ext->user_agent, SSDP_USER_AGENT_LEN, old_ptr);
                  break;
               case SERVER:
                  SSDP_DEBUG_MSG("%s\n", old_ptr);
                  append_value(conf.ext->server, SSDP_SERVER_LEN, old_ptr);
                  break;
               default:
                  break;
               }
               break;
            }
         }
         old_ptr = ptr + 1;
      }
      ptr++;
   }
   return;
}

/**
 * \brief Appends a value to the existing semicolon separated entry.
 * 
 * Appends only values that are not already included in the current entry.
 * 
 * \param [in,out] curr_entry String containing the current entry.
 * \param [in] entry_max Maximum length if the entry.
 * \param [in] value String containing the new entry.
 */
void SSDPPlugin::append_value(char *curr_entry, unsigned entry_max, char *value)
{
   if (strlen(curr_entry) + strlen(value) + 1 < entry_max) {
      if (strstr(curr_entry, value) == NULL) {
         SSDP_DEBUG_MSG("New entry\n");
         strcat(curr_entry, value);
         strcat(curr_entry, ";");
      }
   }
}

/**
 * \brief Parses SSDP payload.
 * 
 * Detects type of message and configures the parser accordingly.
 * 
 * \param [in, out] rec Flow record containing basic flow data.
 * \param [in] pkt Packet struct containing packet data.
 */
void SSDPPlugin::parse_ssdp_message(Flow &rec, const Packet &pkt)
{
   header_parser_conf parse_conf = {
      headers,
      rec.ip_version,
      dynamic_cast<RecordExtSSDP *>(rec.getExtension(ssdp))
   };
   char *data = (char *) pkt.payload;

   total++;
   if (data[0] == 'N') {
      notifies++;
      SSDP_DEBUG_MSG("Notify #%d\n", notifies);
      int notify_headers[] = { NT, LOCATION, SERVER };
      parse_conf.select = notify_headers;
      parse_conf.select_cnt = sizeof(notify_headers) / sizeof(notify_headers[0]);
      parse_headers(data, parse_conf);
   } else if (data[0] == 'M') {
      searches++;
      SSDP_DEBUG_MSG("M-search #%d\n", searches);
      int search_headers[] = { ST, USER_AGENT };
      parse_conf.select = search_headers;
      parse_conf.select_cnt = sizeof(search_headers) / sizeof(search_headers[0]);
      parse_headers(data, parse_conf);
   }
   SSDP_DEBUG_MSG("\n");
}

const char *ipfix_ssdp_template[] = {
   IPFIX_SSDP_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **SSDPPlugin::get_ipfix_string()
{
   return ipfix_ssdp_template;
}

string SSDPPlugin::get_unirec_field_string()
{
   return SSDP_UNIREC_TEMPLATE;
}
