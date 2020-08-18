/**
 * \file passivednsplugin.h
 * \brief Plugin for exporting DNS A and AAAA records.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2017 CESNET
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

#ifndef PASSIVEDNSPLUGIN_H
#define PASSIVEDNSPLUGIN_H

#include <string>
#include <sstream>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "dns.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed DNS packets.
 */
struct RecordExtPassiveDNS : RecordExt {
   uint16_t atype;
   uint16_t id;
   uint8_t ip_version;
   char aname[255];
   uint32_t rr_ttl;
   ipaddr_t ip;

   /**
    * \brief Constructor.
    */
   RecordExtPassiveDNS() : RecordExt(passivedns)
   {
      id = 0;
      atype = 0;
      ip_version = 0;
      aname[0] = 0;
      rr_ttl = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
      ur_set(tmplt, record, F_DNS_ID, id);
      ur_set(tmplt, record, F_DNS_ATYPE, atype);
      ur_set_string(tmplt, record, F_DNS_NAME, aname);
      ur_set(tmplt, record, F_DNS_RR_TTL, rr_ttl);
      if (ip_version == 4) {
         ur_set(tmplt, record, F_DNS_IP, ip_from_4_bytes_be((char *) &ip.v4));
      } else if (ip_version == 6) {
         ur_set(tmplt, record, F_DNS_IP, ip_from_16_bytes_be((char *) ip.v6));
      }
#endif
   }
   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int length;
      int rdata_len = (ip_version == 4 ? 4 : 16);

      length = strlen(aname);
      if (length + rdata_len + 10 > size) {
         return -1;
      }

      *(uint16_t *) (buffer) = ntohs(id);
      *(uint32_t *) (buffer + 2) = ntohl(rr_ttl);
      *(uint16_t *) (buffer + 6) = ntohs(atype);
      buffer[8] = rdata_len;
      if (ip_version == 4) {
         *(uint32_t *) (buffer + 9) = ntohl(ip.v4);
      } else {
         memcpy(buffer + 9, ip.v6, sizeof(ip.v6));
      }
      buffer[9 + rdata_len] = length;
      memcpy(buffer + rdata_len + 10, aname, length);

      return length + rdata_len + 10;
   }
};

/**
 * \brief Flow cache plugin for parsing DNS packets.
 */
class PassiveDNSPlugin : public FlowCachePlugin
{
public:
   PassiveDNSPlugin(const options_t &module_options);
   PassiveDNSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void finish();
   string get_unirec_field_string();
   const char **get_ipfix_string();

private:
   RecordExtPassiveDNS *parse_dns(const char *data, unsigned int payload_len, bool tcp);
   int add_ext_dns(const char *data, unsigned int payload_len, bool tcp, Flow &rec);

   string get_name(const char *data) const;
   size_t get_name_length(const char *data) const;
   bool process_ptr_record(string name, RecordExtPassiveDNS *rec);
   bool str_to_uint4(string str, uint8_t &dst);

   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
   uint32_t total;         /**< Total number of parsed DNS responses. */
   uint32_t parsed_a;      /**< Number of parsed A records. */
   uint32_t parsed_aaaa;   /**< Number of parsed AAAA records. */
   uint32_t parsed_ptr;    /**< Number of parsed PTR records. */

   const char *data_begin; /**< Pointer to begin of payload. */
   uint32_t data_len;      /**< Length of packet payload. */
};

#endif
