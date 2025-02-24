/**
 * \file dnssd.cpp
 * \brief Plugin for parsing DNS-SD traffic.
 * \author Ondrej Sedlacek xsedla1o@stud.fit.vutbr.cz
 * \author Jiri Havranek <havranek@cesnet.cz>
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
 *
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include <errno.h>

#include "dnssd.hpp"

namespace ipxp {

int RecordExtDNSSD::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("dnssd", [](){return new DNSSDPlugin();});
   register_plugin(&rec);
   RecordExtDNSSD::REGISTERED_ID = register_extension();
}

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

DNSSDPlugin::DNSSDPlugin() : txt_all_records(false), queries(0), responses(0), total(0), data_begin(nullptr), data_len(0)
{
}

DNSSDPlugin::~DNSSDPlugin()
{
   close();
}

void DNSSDPlugin::init(const char *params)
{
   DNSSDOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   txt_all_records = parser.m_txt_all;
   if (!parser.m_config_file.empty()) {
      load_txtconfig(parser.m_config_file.c_str());
   }
}

void DNSSDPlugin::close()
{
}

ProcessPlugin *DNSSDPlugin::copy()
{
   return new DNSSDPlugin(*this);
}

int DNSSDPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (pkt.dst_port == 5353 || pkt.src_port == 5353) {
      return add_ext_dnssd(reinterpret_cast<const char *>(pkt.payload), pkt.payload_len, pkt.ip_proto == IPPROTO_TCP, rec);
   }

   return 0;
}

int DNSSDPlugin::post_update(Flow &rec, const Packet &pkt)
{
   if (pkt.dst_port == 5353 || pkt.src_port == 5353) {
      RecordExt *ext = rec.get_extension(RecordExtDNSSD::REGISTERED_ID);

      if (ext == nullptr) {
         return add_ext_dnssd(reinterpret_cast<const char *>(pkt.payload), pkt.payload_len, pkt.ip_proto == IPPROTO_TCP, rec);
      } else {
         parse_dns(reinterpret_cast<const char *>(pkt.payload), pkt.payload_len, pkt.ip_proto == IPPROTO_TCP,
                   static_cast<RecordExtDNSSD *>(ext));
      }
      return 0;
   }

   return 0;
}

void DNSSDPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "DNSSD plugin stats:" << std::endl;
      std::cout << "   Parsed dns queries: " << queries << std::endl;
      std::cout << "   Parsed dns responses: " << responses << std::endl;
      std::cout << "   Total dns packets processed: " << total << std::endl;
   }
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
   std::ifstream in_file;

   in_file.open(config_file);
   if (!in_file) {
      std::ostringstream oss;
      oss <<  strerror(errno) << " '" << config_file << "'";
      throw PluginError(oss.str());
   }
   std::string line, part;
   size_t begin = 0, end = 0;

   while (getline(in_file, line)) {
      begin = end = 0;
      std::pair<std::string, std::list<std::string> > conf;
      end = line.find(",", begin);
      conf.first = line.substr(begin, (end == std::string::npos ? (line.length() - begin)
                                                           : (end - begin)));
      DEBUG_MSG("TXT filter service loaded: %s\n", conf.first.c_str());

      begin = end + 1;
      DEBUG_MSG("TXT filter keys loaded: ");
      while (end != std::string::npos) {
         end = line.find(",", begin);
         part = line.substr(begin, (end == std::string::npos ? (line.length() - begin)
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
std::string DNSSDPlugin::get_name(const char *data) const
{
   std::string name = "";
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

      name += '.' + std::string(data + 1, (uint8_t) data[0]);
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
const std::string DNSSDPlugin::get_service_str(std::string &name) const
{
   size_t begin = name.length();
   int8_t underscore_counter = 0;

   while (underscore_counter < 2 && begin != std::string::npos) {
      begin = name.rfind("_", begin - 1);
      if (begin != std::string::npos) {
         underscore_counter++;
      }
   }
   return name.substr((begin == std::string::npos ? 0 : begin), name.length());
}

/**
 * \brief Checks if Service Instance Name is allowed for TXT processing by checking txt_config.
 * \return True if allowed, otherwise false.
 */
bool DNSSDPlugin::matches_service(std::list<std::pair<std::string, std::list<std::string> > >::const_iterator &it, std::string &name) const
{
   std::string service = get_service_str(name);

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
   std::string name = rdata.name;
   rdata = DnsSdRr();

   switch (type) {
   case DNS_TYPE_PTR:
      DEBUG_MSG("%16s\t\t    %s\n", "PTR", get_name(data).c_str());
      break;
   case DNS_TYPE_SRV:
      {
         struct dns_srv *srv = (struct dns_srv *) data;

         std::string tmp = get_name(data + 6);

         DEBUG_MSG("%16s\t%8u    %s\n", "SRV", ntohs(srv->port), tmp.c_str());

         rdata.srv_port = ntohs(srv->port);
         rdata.srv_target = tmp;
      }
      break;
   case DNS_TYPE_HINFO:
      {
         rdata.hinfo[0] = std::string(data + 1, (uint8_t) data[0]);
         data += ((uint8_t) data[0] + 1);
         rdata.hinfo[1] = std::string(data + 1, (uint8_t) data[0]);
         data += ((uint8_t) data[0] + 1);
         DEBUG_MSG("%16s\t\t    %s, %s\n", "HINFO", rdata.hinfo[0].c_str(), rdata.hinfo[1].c_str());
      }
      break;
   case DNS_TYPE_TXT:
      {
         std::list<std::pair<std::string, std::list<std::string> > >::const_iterator it;
         if (!(txt_all_records || matches_service(it, name))) {  // all_records overrides filter
            break;
         }
         size_t len = (uint8_t) *(data++);
         size_t total_len = len + 1;
         std::list<std::string>::const_iterator sit;
         std::string txt;

         while (length != 0 && total_len <= length) {
            txt = std::string(data, len);

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
         std::string name = get_name(data);

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
         std::string name = get_name(data);

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
         std::string name = get_name(data);

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

         std::string name = get_name(data);

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
void DNSSDPlugin::filtered_append(RecordExtDNSSD *rec, std::string name)
{
   if (name.rfind("arpa") == std::string::npos
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
void DNSSDPlugin::filtered_append(RecordExtDNSSD *rec, std::string name, uint16_t type, DnsSdRr &rdata)
{
   if ((type != DNS_TYPE_SRV && type != DNS_TYPE_HINFO && type != DNS_TYPE_TXT)
       || name.rfind("arpa") != std::string::npos) {
      return;
   }
   std::list<DnsSdRr>::iterator it;

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
            if (!rdata.txt.empty() && it->txt.find(rdata.txt) == std::string::npos) {
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
      rec.add_extension(ext);
   }
   return 0;
}

}
