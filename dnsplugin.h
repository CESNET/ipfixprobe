/**
 * \file dnsplugin.h
 * \brief Plugin for parsing DNS traffic.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
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

#ifndef DNSPLUGIN_H
#define DNSPLUGIN_H

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
struct RecordExtDNS : RecordExt {
   uint16_t id;
   uint16_t answers;
   uint8_t rcode;
   char qname[128];
   uint16_t qtype;
   uint16_t qclass;
   uint32_t rr_ttl;
   uint16_t rlength;
   char data[160];
   uint16_t psize;
   uint8_t dns_do;

   /**
    * \brief Constructor.
    */
   RecordExtDNS() : RecordExt(dns)
   {
      id = 0;
      answers = 0;
      rcode = 0;
      qname[0] = 0;
      qtype = 0;
      qclass = 0;
      rr_ttl = 0;
      rlength = 0;
      data[0] = 0;
      psize = 0;
      dns_do = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
         ur_set(tmplt, record, F_DNS_ID, id);
         ur_set(tmplt, record, F_DNS_ANSWERS, answers);
         ur_set(tmplt, record, F_DNS_RCODE, rcode);
         ur_set_string(tmplt, record, F_DNS_NAME, qname);
         ur_set(tmplt, record, F_DNS_QTYPE, qtype);
         ur_set(tmplt, record, F_DNS_CLASS, qclass);
         ur_set(tmplt, record, F_DNS_RR_TTL, rr_ttl);
         ur_set(tmplt, record, F_DNS_RLENGTH, rlength);
         ur_set_var(tmplt, record, F_DNS_RDATA, data, rlength);
         ur_set(tmplt, record, F_DNS_PSIZE, psize);
         ur_set(tmplt, record, F_DNS_DO, dns_do);
#endif
   }
   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int length;

      length = strlen(qname);
      if (length + rlength + 20 > size) {
         return -1;
      }
      *(uint16_t *) (buffer) = ntohs(answers);
      *(uint8_t *) (buffer + 2) = rcode;
      *(uint16_t *) (buffer + 3) = ntohs(qtype);
      *(uint16_t *) (buffer + 5) = ntohs(qclass);
      *(uint32_t *) (buffer + 7) = ntohl(rr_ttl);
      *(uint16_t *) (buffer + 11) = ntohs(rlength);
      *(uint16_t *) (buffer + 13) = ntohs(psize);
      *(uint8_t *) (buffer + 15) = dns_do;
      *(uint16_t *) (buffer + 16) = ntohs(id);
      buffer[18] = length;
      memcpy(buffer + 19, qname, length);
      buffer[length + 19] = rlength;
      memcpy(buffer + 20 + length, data, rlength);

      return 20 + rlength + length;
   }
};

/**
 * \brief Flow cache plugin for parsing DNS packets.
 */
class DNSPlugin : public FlowCachePlugin
{
public:
   DNSPlugin(const options_t &module_options);
   DNSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void finish();
   string get_unirec_field_string();
   const char **get_ipfix_string();

private:
   bool parse_dns(const char *data, unsigned int payload_len, bool tcp, RecordExtDNS *rec);
   int  add_ext_dns(const char *data, unsigned int payload_len, bool tcp, Flow &rec);
   void process_srv(string &str) const;
   void process_rdata(const char *record_begin, const char *data, ostringstream &rdata, uint16_t type, size_t length) const;

   string get_name(const char *data) const;
   size_t get_name_length(const char *data) const;

   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
   uint32_t queries;       /**< Total number of parsed DNS queries. */
   uint32_t responses;     /**< Total number of parsed DNS responses. */
   uint32_t total;         /**< Total number of parsed DNS packets. */

   const char *data_begin; /**< Pointer to begin of payload. */
   uint32_t data_len;      /**< Length of packet payload. */
};

#endif
