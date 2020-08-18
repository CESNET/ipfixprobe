/**
 * \file httpsplugin.cpp
 * \brief Plugin for parsing https traffic.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2018 CESNET
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

#include "httpsplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "ipfix-elements.h"

using namespace std;

#define HTTPS_UNIREC_TEMPLATE "HTTPS_SNI"

UR_FIELDS (
   string HTTPS_SNI
)

HTTPSPlugin::HTTPSPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
   parsed_sni = 0;
   total = 0;
   flow_flush = false;
   ext_ptr = NULL;
}

HTTPSPlugin::HTTPSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   parsed_sni = 0;
   total = 0;
   flow_flush = false;
   ext_ptr = NULL;
}
HTTPSPlugin::~HTTPSPlugin()
{
   if (ext_ptr != NULL) {
      delete ext_ptr;
   }
}

int HTTPSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (rec.src_port == 443 || rec.dst_port == 443) {
      add_https_record(rec, pkt);
   }

   return 0;
}

int HTTPSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   if (rec.src_port == 443 || rec.dst_port == 443) {
      RecordExt *ext = rec.getExtension(https);
      if (ext != NULL) {
         return FLOW_FLUSH_WITH_REINSERT;
      }
      add_https_record(rec, pkt);
   }

   return 0;
}

bool HTTPSPlugin::parse_sni(const char *data, int payload_len, RecordExtHTTPS *rec)
{
   const char *data_end = data + payload_len;
   tls_rec *tls = (tls_rec *) data;

   total++;
   if (payload_len - sizeof(tls_rec) < 0 || tls->type != TLS_HANDSHAKE ||
         tls->version.major != 3 || tls->version.minor > 3) {
      return false;
   }
   data += sizeof(tls_rec);

   tls_handshake *tls_hs = (tls_handshake *) data;
   if (data + sizeof(tls_handshake) > data_end || tls_hs->type != TLS_HANDSHAKE_CLIENT_HELLO) {
      return false;
   }

   uint32_t hs_len = tls_hs->length1 << 16 | ntohs(tls_hs->length2);
   if (data + hs_len > data_end || tls_hs->version.major != 3 ||
      tls_hs->version.minor < 1 || tls_hs->version.minor > 3) {
      return false;
   }
   data += sizeof(tls_handshake);

   data += 32; // Skip random

   int tmp = *(uint8_t *) data;
   if (data + tmp + 2 > data_end) {
      return false;
   }

   data += tmp + 1; // Skip session id
   tmp = ntohs(*(uint16_t *) data);
   if (data + tmp + 1 > data_end) {
      return false;
   }

   data += tmp + 2; // Skip cipher suites
   tmp = *(uint8_t *) data;
   if (data + tmp + 2 > data_end) {
      return false;
   }

   data += tmp + 1; // Skip compression methods

   const char *ext_end = data + ntohs(*(uint16_t *) data);
   data += 2;

   if (ext_end > data_end) {
      return false;
   }

   while (data + sizeof(tls_ext) < ext_end) {
      tls_ext *ext = (tls_ext *) data;
      uint16_t length = ntohs(ext->length);

      data += sizeof(tls_ext);
      if (ntohs(ext->type) == TLS_EXT_SERVER_NAME) {
         const char *list_end = data + ntohs(*(uint16_t *) data) + 2;
         int sni_parsed = 0;
         data += 2;

         if (list_end > data_end) {
            return false;
         }

         while (data + sizeof(tls_ext_sni) < list_end) {
            tls_ext_sni *sni = (tls_ext_sni *) data;
            uint16_t sni_len = ntohs(sni->length);

            data += sizeof(tls_ext_sni);
            if (data + ntohs(sni->length) > list_end) {
               return sni_parsed != 0;
            }
            if (rec->sni[0] != 0) {
               RecordExtHTTPS *tmp_rec = new RecordExtHTTPS();
               rec->next = tmp_rec;
               rec = tmp_rec;
            }
            memcpy(rec->sni, data, sni_len);
            rec->sni[sni_len] = 0;
            sni_parsed++;
            parsed_sni++;
         }
         return sni_parsed != 0;
      }

      data += length;
   }

   return false;
}

void HTTPSPlugin::add_https_record(Flow &rec, const Packet &pkt)
{
   if (ext_ptr == NULL) {
      ext_ptr = new RecordExtHTTPS();
   }

   if (parse_sni(pkt.payload, pkt.payload_length, ext_ptr)) {
      rec.addExtension(ext_ptr);
      ext_ptr = NULL;
   }
}

void HTTPSPlugin::finish()
{
   if (print_stats) {
      cout << "HTTPS plugin stats:" << endl;
      cout << "   Total HTTPS packets seen: " << total << endl;
      cout << "   Parsed SNI: " << parsed_sni << endl;
   }
}

const char *ipfix_https_template[] = {
   IPFIX_HTTPS_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **HTTPSPlugin::get_ipfix_string()
{
   return ipfix_https_template;
}

string HTTPSPlugin::get_unirec_field_string()
{
   return HTTPS_UNIREC_TEMPLATE;
}

bool HTTPSPlugin::include_basic_flow_fields()
{
   return true;
}

