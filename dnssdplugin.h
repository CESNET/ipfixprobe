/**
 * \file dnssdplugin.h
 * \brief Plugin for parsing dnssd traffic.
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

#ifndef DNSSDPLUGIN_H
#define DNSSDPLUGIN_H

#include <string>
#include <sstream>
#include <fstream>
#include <list>
#include <algorithm>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "dns.h"

using namespace std;

struct DnsSdRr {
   string name;
   int32_t srv_port;
   string srv_target;
   string hinfo[2];
   string txt;

   /**
    * \brief Constructor.
    */
   DnsSdRr() {
      name = string();
      srv_port = -1;
      srv_target = string();
      hinfo[0] = string();
      txt = string();
   }
};

/**
 * \brief Flow record extension header for storing parsed DNSSD packets.
 */
struct RecordExtDNSSD : RecordExt {
   list<string> queries;
   list<DnsSdRr> responses;

   /**
    * \brief Constructor.
    */
   RecordExtDNSSD() : RecordExt(dnssd)
   {
   }

   /**
    * \brief Concatenates all collected queries to a single string.
    * \param [in] max_length Size limit for the output string.
    * \return String of semicolon separated queries.
    * 
    * The string will allways contain complete entries.
    */
   string queries_to_string(size_t max_length) {
      list<string>::iterator it;
      string ret;

      for (it = queries.begin(); it != queries.end(); it++) {
         if (max_length == string::npos) {
            ret += *it + ";";
         } else {
            if (ret.length() + (*it).length() + 1 <= max_length) {
               ret += *it + ";";
            } else {
               break;
            }
         }
      }
      return ret;
   }

   /**
    * \brief Converts a response to semicolon separated string.
    * \param [in] response Iterator pointing at the response.
    */
   string response_to_string(list<DnsSdRr>::iterator response){
      stringstream ret;

      ret << response->name + ";";
      ret << response->srv_port << ";";
      ret << response->srv_target + ";";
      if (!(response->hinfo[0].empty() && response->hinfo[1].empty())) {
         ret << response->hinfo[0] << ":" << response->hinfo[1] + ";";
      } else {
         ret << ";";
      }
      ret << response->txt + ";";
      return ret.str();
   }

   /**
    * \brief Concatenates all collected responses to single string.
    * \param [in] max_length Size limit for the output string.
    * \return String of semicolon separated responses.
    * 
    * The string will allways contain complete entries.
    */
   string responses_to_string(size_t max_length) {
      list<DnsSdRr>::iterator it;
      string ret, part;

      for (it = responses.begin(); it != responses.end(); it++) {
         if (max_length == string::npos) {
            ret += response_to_string(it);
         } else {
            part = response_to_string(it);
            if (ret.length() + part.length() + 1 <= max_length) {
               ret += part;
            } else {
               break;
            }
         }
      }
      return ret;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
      ur_set_string(tmplt, record, F_DNSSD_QUERIES, queries_to_string(string::npos).c_str());
      ur_set_string(tmplt, record, F_DNSSD_RESPONSES, responses_to_string(string::npos).c_str());
#endif
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      string queries = queries_to_string(510);
      string responses = responses_to_string(510);

      int length = 0;
      int qry_len = queries.length();
      int resp_len = responses.length();

      if (qry_len + resp_len + 6 > size) {
         return -1;
      }

      if (qry_len >= 255) {
         buffer[length++] = 255;
         *(uint16_t *)(buffer + length) = ntohs(qry_len);
         length += sizeof(uint16_t);
      } else {
         buffer[length++] = qry_len;
      }
      memcpy(buffer + length, queries.c_str(), qry_len);
      length += qry_len;
      
      if (resp_len >= 255) {
         buffer[length++] = 255;
         *(uint16_t *)(buffer + length) = ntohs(resp_len);
         length += sizeof(uint16_t);
      } else {
         buffer[length++] = resp_len;
      }
      memcpy(buffer + length, responses.c_str(), resp_len);
      length += resp_len;

      return length;
   }
};

/**
 * \brief Flow cache plugin for parsing DNSSD packets.
 */
class DNSSDPlugin : public FlowCachePlugin
{
public:
   DNSSDPlugin(const options_t &module_options);
   DNSSDPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();

private:
   bool parse_dns(const char *data, unsigned int payload_len, bool tcp, RecordExtDNSSD *rec);
   int  add_ext_dnssd(const char *data, unsigned int payload_len, bool tcp, Flow &rec);
   void process_rdata(const char *record_begin, const char *data, DnsSdRr &rdata, uint16_t type, size_t length) const;
   void filtered_append(RecordExtDNSSD *rec, string name);
   void filtered_append(RecordExtDNSSD *rec, string name, uint16_t type, DnsSdRr &rdata);

   string get_name(const char *data) const;
   size_t get_name_length(const char *data) const;
   const string get_service_str(string &name) const;

   bool parse_params(const string &params, string &config_file);
   void load_txtconfig(const char *config_file);
   bool matches_service(list<pair<string, list<string> > >::const_iterator &it, string &name) const;

   list<pair<string, list<string> > > txt_config;   /**< Configuration for TXT record filter. */
   bool txt_all_records;   /**< Indicator whether to process all TXT recods. */ 

   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
   uint32_t queries;       /**< Total number of parsed DNS queries. */
   uint32_t responses;     /**< Total number of parsed DNS responses. */
   uint32_t total;         /**< Total number of parsed DNS packets. */

   const char *data_begin; /**< Pointer to begin of payload. */
   uint32_t data_len;      /**< Length of packet payload. */
};

#endif
