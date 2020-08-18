/**
 * \file dnssdplugin.cpp
 * \brief Plugin for parsing DNS-SD traffic.
 * \author Ondrej Sedlacek xsedla1o@stud.fit.vutbr.cz
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
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

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <unirec/unirec.h>
#include <errno.h>

#include "dnssdplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "ipfix-elements.h"

using namespace std;

// #define DEBUG_DNSSD

// Print debug message if debugging is allowed.
#ifdef DEBUG_DNSSD
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_DNSSD
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

/**
 * \brief Check for label pointer in DNS name.
 */
#define IS_POINTER(ch) ((ch & 0xC0) == 0xC0)

#define MAX_LABEL_CNT 127

/**
 * \brief Get offset from 2 byte pointer.
 */
#define GET_OFFSET(half1, half2) ((((uint8_t)(half1) & 0x3F) << 8) | (uint8_t)(half2))

#define DNSSD_UNIREC_TEMPLATE "DNSSD_QUERIES,DNSSD_RESPONSES"

UR_FIELDS (
   string DNSSD_QUERIES
   string DNSSD_RESPONSES
)

/**
 * \brief Constructor.
 * \param [in] options Module options.
 */
DNSSDPlugin::DNSSDPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
   queries = 0;
   responses = 0;
   total = 0;
   txt_all_records = false;
}

DNSSDPlugin::DNSSDPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   queries = 0;
   responses = 0;
   total = 0;
   txt_all_records = false;
   string config_file;
   if (parse_params(plugin_options[0].params, config_file)) {
      load_txtconfig(config_file.c_str());
   }
}

bool DNSSDPlugin::parse_params(const string &params, string &config_file)
{
   DEBUG_MSG("Recieved parameters: %s\n", params.c_str());
   size_t begin = 0, end = 0, sep = 0;
   string key, val;

   while (end != string::npos) {
      sep = params.find("=", begin);
      end = params.find(":", begin);
      if (end < sep) {
         sep = string::npos;
      }
      key = params.substr(begin, (sep == string::npos ? (end == string::npos ? (params.length() - end)
                                                                             : (end))
                                                      : (sep - begin)));
      key.erase(remove_if(key.begin(), key.end(), ::isspace), key.end());
      if (!key.empty()) {
         if (sep++ != string::npos) {
            val = params.substr(sep, (end == string::npos ? (params.length() - end) : (end - sep)));
         }
         if (key == "txt") {
            if (!val.empty()) {
               config_file = val;
               return true;
            } else {
               txt_all_records = true;
               DEBUG_MSG("Enabled processing of all TXT records.\n");
               return false;
            }
         } else {
            cerr << "flow_meter: dnssd: Warning - ignoring parameter with key: " << key << endl;
         }
      }
      begin = end + 1;
   }
   return false;
}

int DNSSDPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (pkt.dst_port == 5353 || pkt.src_port == 5353) {
      return add_ext_dnssd(pkt.payload, pkt.payload_length, pkt.ip_proto == IPPROTO_TCP, rec);
   }

   return 0;
}

int DNSSDPlugin::post_update(Flow &rec, const Packet &pkt)
{
   if (pkt.dst_port == 5353 || pkt.src_port == 5353) {
      RecordExt *ext = rec.getExtension(dnssd);

      if (ext == NULL) {
         return add_ext_dnssd(pkt.payload, pkt.payload_length, pkt.ip_proto == IPPROTO_TCP, rec);
      } else {
         parse_dns(pkt.payload, pkt.payload_length, pkt.ip_proto == IPPROTO_TCP,
                   dynamic_cast<RecordExtDNSSD *>(ext));
      }
      return 0;
   }

   return 0;
}

void DNSSDPlugin::finish()
{
   if (print_stats) {
      cout << "DNSSD plugin stats:" << endl;
      cout << "   Parsed dns queries: " << queries << endl;
      cout << "   Parsed dns responses: " << responses << endl;
      cout << "   Total dns packets processed: " << total << endl;
   }
}

string DNSSDPlugin::get_unirec_field_string()
{
   return DNSSD_UNIREC_TEMPLATE;
}

const char *ipfix_dnssd_template[] = {
   IPFIX_DNSSD_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **DNSSDPlugin::get_ipfix_string()
{
   return ipfix_dnssd_template;
}

/**
 * \brief Load configuration for TXT filtering.
 * 
 * Takes path to file from enviroment variable DNSSD_TXTCONFIG_PATH.
 */
void DNSSDPlugin::load_txtconfig(const char *config_file)
{
   if (!config_file) {
      return;
   }
   ifstream in_file;

   in_file.open(config_file);
   if (!in_file) {
      cerr << "flow_meter: dnssd plugin: " << strerror(errno) << " '" << config_file << "'\n";
      return;
   }
   string line, part;
   size_t begin = 0, end = 0;

   while (getline(in_file, line)) {
      begin = end = 0;
      std::pair<string, list<string> > conf;
      end = line.find(",", begin);
      conf.first = line.substr(begin, (end == string::npos ? (line.length() - begin)
                                                           : (end - begin)));
      DEBUG_MSG("TXT filter service loaded: %s\n", conf.first.c_str());

      begin = end + 1;
      DEBUG_MSG("TXT filter keys loaded: ");
      while (end != string::npos) {
         end = line.find(",", begin);
         part = line.substr(begin, (end == string::npos ? (line.length() - begin) 
                                                        : (end - begin)));
         conf.second.push_back(part);
         DEBUG_MSG("%s ", part.c_str());
         begin = end + 1;
      }
      DEBUG_MSG("\n");
      txt_config.push_back(conf);
   }
   in_file.close();
}

/**
 * \brief Get name length.
 * \param [in] data Pointer to string.
 * \return Number of characters in string.
 */
size_t DNSSDPlugin::get_name_length(const char *data) const
{
   size_t len = 0;

   while (1) {
      if ((uint32_t) (data - data_begin) + 1 > data_len) {
         throw "Error: overflow";
      }
      if (!data[0]) {
         break;
      }
      if (IS_POINTER(data[0])) {
         return len + 2;
      }

      len += (uint8_t) data[0] + 1;
      data += (uint8_t) data[0] + 1;
   }

   return len + 1;
}

/**
 * \brief Decompress dns name.
 * \param [in] data Pointer to compressed data.
 * \return String with decompressed dns name.
 */
string DNSSDPlugin::get_name(const char *data) const
{
   string name = "";
   int label_cnt = 0;

   if ((uint32_t) (data - data_begin) > data_len) {
      throw "Error: overflow";
   }

   while (data[0]) {            /* Check for terminating character. */
      if (IS_POINTER(data[0])) {        /* Check for label pointer (11xxxxxx byte) */
         data = data_begin + GET_OFFSET(data[0], data[1]);

         /* Check for possible errors. */
         if (label_cnt++ > MAX_LABEL_CNT || (uint32_t) (data - data_begin) > data_len) {
            throw "Error: label count exceed or overflow";
         }

         continue;
      }

      /* Check for possible errors. */
      if (label_cnt++ > MAX_LABEL_CNT || (uint8_t) data[0] > 63 ||
          (uint32_t) ((data - data_begin) + (uint8_t) data[0] + 2) > data_len) {
         throw "Error: label count exceed or overflow";
      }

      name += '.' + string(data + 1, (uint8_t) data[0]);
      data += ((uint8_t) data[0] + 1);
   }

   if (name[0] == '.') {
      name.erase(0, 1);
   }

   return name;
}

/**
 * \brief Returns a DNS Service Instance Name without the <Instance> part.
 * \param [in] name DNS Service Instance Name.
 * 
 * Service Instance Name = <Instance> . <Service> . <Domain>
 * As an example, given input "My MacBook Air._device-info._tcp.local"
 * returns "_device-info._tcp.local".
 */
const string DNSSDPlugin::get_service_str(string &name) const
{
   size_t begin = name.length();
   int8_t underscore_counter = 0;

   while (underscore_counter < 2 && begin != string::npos) {
      begin = name.rfind("_", begin - 1);
      if (begin != string::npos) {
         underscore_counter++;
      }
   }
   return name.substr((begin == string::npos ? 0 : begin), name.length());
}

/**
 * \brief Checks if Service Instance Name is allowed for TXT processing by checking txt_config.
 * \return True if allowed, otherwise false.
 */
bool DNSSDPlugin::matches_service(list<pair<string, list<string> > >::const_iterator &it, string &name) const
{
   string service = get_service_str(name);

   for (it = txt_config.begin(); it != txt_config.end(); it++) {
      if (it->first == service) {
         return true;
      }
   }
   return false;
}

/**
 * \brief Process RDATA section.
 * \param [in] record_begin Pointer to start of current resource record.
 * \param [in] data Pointer to RDATA section.
 * \param [out] rdata String which stores processed data.
 * \param [in] type Type of RDATA section.
 * \param [in] length Length of RDATA section.
 */
void DNSSDPlugin::process_rdata(const char *record_begin, const char *data, DnsSdRr &rdata, uint16_t type, size_t length) const
{
   string name = rdata.name;
   rdata = DnsSdRr();

   switch (type) {
   case DNS_TYPE_PTR:
      DEBUG_MSG("%16s\t\t    %s\n", "PTR", get_name(data).c_str());
      break;
   case DNS_TYPE_SRV:
      {
         struct dns_srv *srv = (struct dns_srv *) data;

         string tmp = get_name(data + 6);

         DEBUG_MSG("%16s\t%8u    %s\n", "SRV", ntohs(srv->port), tmp.c_str());

         rdata.srv_port = ntohs(srv->port);
         rdata.srv_target = tmp;
      }
      break;
   case DNS_TYPE_HINFO:
      {
         rdata.hinfo[0] = string(data + 1, (uint8_t) data[0]);
         data += ((uint8_t) data[0] + 1);
         rdata.hinfo[1] = string(data + 1, (uint8_t) data[0]);
         data += ((uint8_t) data[0] + 1);
         DEBUG_MSG("%16s\t\t    %s, %s\n", "HINFO", rdata.hinfo[0].c_str(), rdata.hinfo[1].c_str());
      }
      break;
   case DNS_TYPE_TXT:
      {
         list<pair<string, list<string> > >::const_iterator it;
         if (!(txt_all_records || matches_service(it, name))) {  // all_records overrides filter
            break;
         }
         size_t len = (uint8_t) *(data++);
         size_t total_len = len + 1;
         list<string>::const_iterator sit;
         string txt;

         while (length != 0 && total_len <= length) {
            txt = string(data, len);

            if (txt_all_records) {
               DEBUG_MSG("%16s\t\t    %s\n", "TXT", txt.c_str());
               rdata.txt += txt + ":";
            } else {
                  for (sit = it->second.begin(); sit != it->second.end(); sit++) {
                  if (*sit == txt.substr(0, txt.find("="))) {
                     DEBUG_MSG("%16s\t\t    %s\n", "TXT", txt.c_str());
                     rdata.txt += txt + ":";
                     break;
                  }
               }
            }

            data += len;
            len = (uint8_t) *(data++);
            total_len += len + 1;
         }
      }
      break;
   default:
      break;
   }
}

#ifdef DEBUG_DNSSD
uint32_t s_queries = 0;
uint32_t s_responses = 0;
#endif /* DEBUG_DNSSD */

/**
 * \brief Parse and store DNS packet.
 * \param [in] data Pointer to packet payload section.
 * \param [in] payload_len Payload length.
 * \param [in] tcp DNS over tcp.
 * \param [out] rec Output Flow extension header.
 * \return True if DNS was parsed.
 */
bool DNSSDPlugin::parse_dns(const char *data, unsigned int payload_len, bool tcp, RecordExtDNSSD *rec)
{
   try {
      total++;

      DEBUG_MSG("---------- dns parser #%u ----------\n", total);
      DEBUG_MSG("Payload length: %u\n", payload_len);

      if (tcp) {
         payload_len -= 2;
         if (ntohs(*(uint16_t *) data) != payload_len) {
            DEBUG_MSG("parser quits: fragmented tcp pkt");
            return false;
         }
         data += 2;
      }

      if (payload_len < sizeof(struct dns_hdr)) {
         DEBUG_MSG("parser quits: payload length < %ld\n", sizeof(struct dns_hdr));
         return false;
      }

      data_begin = data;
      data_len = payload_len;

      struct dns_hdr *dns = (struct dns_hdr *) data;
      uint16_t flags = ntohs(dns->flags);
      uint16_t question_cnt = ntohs(dns->question_rec_cnt);
      uint16_t answer_rr_cnt = ntohs(dns->answer_rec_cnt);
      uint16_t authority_rr_cnt = ntohs(dns->name_server_rec_cnt);
      uint16_t additional_rr_cnt = ntohs(dns->additional_rec_cnt);

      DEBUG_MSG("%s number: %u\n",                    DNS_HDR_GET_QR(flags) ? "Response" : "Query",
                                                      DNS_HDR_GET_QR(flags) ? s_queries++ : s_responses++);
      DEBUG_MSG("DNS message header\n");
      DEBUG_MSG("\tFlags:\t\t\t%#06x\n",              ntohs(dns->flags));

      DEBUG_MSG("\t\tQuestion/reply:\t\t%u (%s)\n",   DNS_HDR_GET_QR(flags),
                                                      DNS_HDR_GET_QR(flags) ? "Response" : "Query");
      DEBUG_MSG("\t\tAuthoritative answer:\t%u\n",    DNS_HDR_GET_AA(flags));

      DEBUG_MSG("\tQuestions:\t\t%u\n",               question_cnt);
      DEBUG_MSG("\tAnswer RRs:\t\t%u\n",              answer_rr_cnt);
      DEBUG_MSG("\tAuthority RRs:\t\t%u\n",           authority_rr_cnt);
      DEBUG_MSG("\tAdditional RRs:\t\t%u\n",          additional_rr_cnt);

      /********************************************************************
      *****                   DNS Question section                    *****
      ********************************************************************/
      data += sizeof(struct dns_hdr);
      for (int i = 0; i < question_cnt; i++) {
         DEBUG_CODE(if (i == 0) {
            DEBUG_MSG("\nDNS questions section\n");
            DEBUG_MSG("%8s%8s%8s%8s%8s\n", "num", "type", "ttl", "port", "name");
         });
         string name = get_name(data);

         data += get_name_length(data);
         DEBUG_CODE(struct dns_question *question = (struct dns_question *) data);

         if ((data - data_begin) + sizeof(struct dns_question) > payload_len) {
            DEBUG_MSG("DNS parser quits: overflow\n\n");
            return 1;
         }

         filtered_append(rec, name);

         DEBUG_MSG("#%7d%8u%20s%s\n", i + 1, ntohs(question->qtype), "", name.c_str());
         data += sizeof(struct dns_question);
      }

      /********************************************************************
      *****                    DNS Answers section                    *****
      ********************************************************************/
      const char *record_begin;
      size_t rdlength;
      DnsSdRr rdata;

      for (int i = 0; i < answer_rr_cnt; i++) { // Process answers section.
         if (i == 0) {
            DEBUG_MSG("DNS answers section\n");
            DEBUG_MSG("%8s%8s%8s%8s%8s\n", "num", "type", "ttl", "port", "name");
         }

         record_begin = data;
         string name = get_name(data);

         data += get_name_length(data);

         struct dns_answer *answer = (struct dns_answer *) data;

         uint32_t tmp = (data - data_begin) + sizeof(dns_answer);

         if (tmp > payload_len || tmp + ntohs(answer->rdlength) > payload_len) {
            DEBUG_MSG("DNS parser quits: overflow\n\n");
            return 1;
         }
         DEBUG_MSG("#%7d%8u%8u%12s%s\n", i + 1, ntohs(answer->atype), ntohl(answer->ttl), "",
                   name.c_str());

         data += sizeof(struct dns_answer);
         rdlength = ntohs(answer->rdlength);
         rdata.name = name;

         process_rdata(record_begin, data, rdata, ntohs(answer->atype), rdlength);
         if (DNS_HDR_GET_QR(flags)) {   // Ignore the known answers in a query.
            filtered_append(rec, name, ntohs(answer->atype), rdata);
         }
         data += rdlength;
      }

      /********************************************************************
      *****                 DNS Authority RRs section                 *****
      ********************************************************************/

      for (int i = 0; i < authority_rr_cnt; i++) {
         DEBUG_CODE(if (i == 0) {
            DEBUG_MSG("DNS authority RRs section\n");
            DEBUG_MSG("%8s%8s%8s%8s%8s\n", "num", "type", "ttl", "port", "name");
         });

         record_begin = data;
         string name = get_name(data);

         data += get_name_length(data);

         struct dns_answer *answer = (struct dns_answer *) data;

         uint32_t tmp = (data - data_begin) + sizeof(dns_answer);

         if (tmp > payload_len || tmp + ntohs(answer->rdlength) > payload_len) {
            DEBUG_MSG("DNS parser quits: overflow\n\n");
            return 1;
         }

         DEBUG_MSG("#%7d%8u%8u%12s%s\n", i + 1, ntohs(answer->atype), ntohl(answer->ttl), "",
                   name.c_str());


         data += sizeof(struct dns_answer);
         rdlength = ntohs(answer->rdlength);
         rdata.name = name;

         process_rdata(record_begin, data, rdata, ntohs(answer->atype), rdlength);
         filtered_append(rec, name, ntohs(answer->atype), rdata);

         data += rdlength;
      }

      /********************************************************************
      *****                 DNS Additional RRs section                *****
      ********************************************************************/
      for (int i = 0; i < additional_rr_cnt; i++) {
         DEBUG_CODE(if (i == 0) {
            DEBUG_MSG("DNS additional RRs section\n");
            DEBUG_MSG("%8s%8s%8s%8s%8s\n", "num", "type", "ttl", "port", "name");
         });

         record_begin = data;

         string name = get_name(data);

         data += get_name_length(data);

         struct dns_answer *answer = (struct dns_answer *) data;

         uint32_t tmp = (data - data_begin) + sizeof(dns_answer);

         if (tmp > payload_len || tmp + ntohs(answer->rdlength) > payload_len) {
            DEBUG_MSG("DNS parser quits: overflow\n\n");
            return 1;
         }

         DEBUG_MSG("#%7d%8u%8u%12s%s\n", i + 1, ntohs(answer->atype), ntohl(answer->ttl), "",
                   name.c_str());

         rdlength = ntohs(answer->rdlength);

         if (ntohs(answer->atype) != DNS_TYPE_OPT) {

            data += sizeof(struct dns_answer);
            rdata.name = name;

            process_rdata(record_begin, data, rdata, ntohs(answer->atype), rdlength);
            if (DNS_HDR_GET_QR(flags)) {
               filtered_append(rec, name, ntohs(answer->atype), rdata);
            }
         }

         data += rdlength;
      }

      if (DNS_HDR_GET_QR(flags)) {
         responses++;
      } else {
         queries++;
      }

      DEBUG_MSG("DNS parser quits: parsing done\n\n");
   }
   catch(const char *err) {
      DEBUG_MSG("%s\n", err);
      return false;
   }

   return true;
}

/**
 * \brief Append new unique query to DNSSD extension record.
 * \param [in,out] rec Pointer to DNSSD extension record
 * \param [in] name Domain name of the DNS record.
 */
void DNSSDPlugin::filtered_append(RecordExtDNSSD *rec, string name)
{
   if (name.rfind("arpa") == string::npos
       && std::find(rec->queries.begin(), rec->queries.end(), name) == rec->queries.end()) {
      rec->queries.push_back(name);
   }
}

/**
 * \brief Append new unique response to DNSSD extension record.
 * \param [in,out] rec Pointer to DNSSD extension record
 * \param [in] name Domain name of the DNS record.
 * \param [in] type DNS type id of the DNS record.
 * \param [in] rdata RDATA of the DNS record.
 */
void DNSSDPlugin::filtered_append(RecordExtDNSSD *rec, string name, uint16_t type, DnsSdRr &rdata)
{
   if ((type != DNS_TYPE_SRV && type != DNS_TYPE_HINFO && type != DNS_TYPE_TXT)
       || name.rfind("arpa") != string::npos) {
      return;
   }
   list<DnsSdRr>::iterator it;

   for (it = rec->responses.begin(); it != rec->responses.end(); it++) {
      if (it->name == name) {
         switch (type) {
         case DNS_TYPE_SRV:
            it->srv_port = rdata.srv_port;
            it->srv_target = rdata.srv_target;
            return;
         case DNS_TYPE_HINFO:
            it->hinfo[0] = rdata.hinfo[0];
            it->hinfo[1] = rdata.hinfo[1];
            return;
         case DNS_TYPE_TXT:
            if (!rdata.txt.empty() && it->txt.find(rdata.txt) == string::npos) {
               it->txt += rdata.txt + ":";
            }
            return;
         default:
            return;
         }
      }
   }

   DnsSdRr rr;

   rr.name = name;
   switch (type) {
   case DNS_TYPE_SRV:
      rr.srv_port = rdata.srv_port;
      rr.srv_target = rdata.srv_target;
      break;
   case DNS_TYPE_HINFO:
      rr.hinfo[0] = rdata.hinfo[0];
      rr.hinfo[1] = rdata.hinfo[1];
      break;
   case DNS_TYPE_TXT:
      rr.txt = rdata.txt;
      break;
   default:
      return;
   }
   rec->responses.push_back(rr);
}

/**
 * \brief Add new extension DNSSD header into Flow.
 * \param [in] data Pointer to packet payload section.
 * \param [in] payload_len Payload length.
 * \param [in] tcp DNS over tcp.
 * \param [out] rec Destination Flow.
 */
int DNSSDPlugin::add_ext_dnssd(const char *data, unsigned int payload_len, bool tcp, Flow &rec)
{
   RecordExtDNSSD *ext = new RecordExtDNSSD();

   if (!parse_dns(data, payload_len, tcp, ext)) {
      delete ext;

      return 0;
   } else {
      rec.addExtension(ext);
   }
   return 0;
}
