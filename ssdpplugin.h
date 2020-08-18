/**
 * \file ssdpplugin.h
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

#ifndef SSDPPLUGIN_H
#define SSDPPLUGIN_H

#include <string>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"

using namespace std;

#define SSDP_URN_LEN 511
#define SSDP_SERVER_LEN 255
#define SSDP_USER_AGENT_LEN 255

/**
 * \brief Flow record extension header for storing parsed SSDP packets.
 */
struct RecordExtSSDP : RecordExt {
   uint16_t port;
   char nt[SSDP_URN_LEN];
   char st[SSDP_URN_LEN];
   char server[SSDP_SERVER_LEN];
   char user_agent[SSDP_USER_AGENT_LEN];

   /**
    * \brief Constructor.
    */
   RecordExtSSDP() : RecordExt(ssdp)
   {
      port = 0;
      nt[0] = 0;
      st[0] = 0;
      server[0] = 0;
      user_agent[0]= 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
      ur_set(tmplt, record, F_SSDP_LOCATION_PORT, port);
      ur_set_string(tmplt, record, F_SSDP_NT, nt);
      ur_set_string(tmplt, record, F_SSDP_SERVER, server);
      ur_set_string(tmplt, record, F_SSDP_ST, st);
      ur_set_string(tmplt, record, F_SSDP_USER_AGENT, user_agent);
#endif
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int length = 2;

      int nt_len = strlen(nt);
      int server_len = strlen(server);
      int st_len = strlen(st);
      int user_agent_len = strlen(user_agent);

      if (length + nt_len + server_len + st_len + user_agent_len + 8 > size) {
         return -1;
      }

      *(uint16_t *) (buffer) = ntohs(port);

      if (nt_len >= 255) {
         buffer[length++] = 255;
         *(uint16_t *)(buffer + length) = ntohs(nt_len);
         length += sizeof(uint16_t);
      } else {
         buffer[length++] = nt_len;
      }
      memcpy(buffer + length, nt, nt_len);
      length += nt_len;

      buffer[length++] = server_len;
      memcpy(buffer + length, server, server_len);
      length += server_len;

      if (st_len >= 255) {
         buffer[length++] = 255;
         *(uint16_t *)(buffer + length) = ntohs(st_len);
         length += sizeof(uint16_t);
      } else {
         buffer[length++] = st_len;
      }
      memcpy(buffer + length, st, st_len);
      length += st_len;

      buffer[length++] = user_agent_len;
      memcpy(buffer + length, user_agent, user_agent_len);
      length += user_agent_len;

      return length;
   }
};

/**
 * \brief Flow cache plugin for parsing SSDP packets.
 */
class SSDPPlugin : public FlowCachePlugin
{
public:
   SSDPPlugin(const options_t &module_options);
   SSDPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();

   /**
    * \brief Struct passed to parse_headers function.
    */
   struct header_parser_conf {
      const char **headers;   /**< Pointer to array of header strings. */
      uint8_t ip_version;     /**< IP version of source IP address. */
      RecordExtSSDP *ext;     /**< Pointer to allocated record exitension. */
      unsigned select_cnt;    /**< Number of selected headers. */
      int *select;            /**< Array of selected header indices. */
   } ;

private:
   uint16_t parse_loc_port(char *data, uint8_t ip_version);
   bool get_header_val(char **data, const char *header, const int len);
   void parse_headers(char *data, header_parser_conf conf);
   void parse_ssdp_message(Flow &rec, const Packet &pkt);
   void append_value(char *curr_entry, unsigned entry_max, char *value);

   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
   uint32_t notifies;      /**< Total number of parsed SSDP notifies. */
   uint32_t searches;      /**< Total number of parsed SSDP m-searches. */
   uint32_t total;         /**< Total number of parsed SSDP packets. */
   RecordExtSSDP *record;  /**< Pointer to allocated record extension */
};

#endif
