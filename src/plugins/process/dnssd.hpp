/**
 * \file dnssd.hpp
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
 *
 *
 */

#ifndef IPXP_PROCESS_DNSSD_HPP
#define IPXP_PROCESS_DNSSD_HPP

#include <string>
#include <cstring>
#include <sstream>
#include <fstream>
#include <list>
#include <algorithm>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include "dns-utils.hpp"

namespace ipxp {

#define DNSSD_UNIREC_TEMPLATE "DNSSD_QUERIES,DNSSD_RESPONSES"

UR_FIELDS (
   string DNSSD_QUERIES
   string DNSSD_RESPONSES
)

class DNSSDOptParser : public OptionsParser
{
public:
   bool m_txt_all;
   std::string m_config_file;

   DNSSDOptParser() : OptionsParser("dnssd", "Processing plugin for parsing DNS service discovery packets"), m_txt_all(false), m_config_file("")
   {
      register_option("t", "txt", "FILE", "Activates processing of all txt records. Allow to specify whitelist txt records file (file line format: service.domain,txt_key1,txt_key2,...)",
         [this](const char *arg){
            m_txt_all = true;
            if (arg != nullptr) {m_config_file = arg;}
            return true;
         }, OptionFlags::OptionalArgument);
   }
};

struct DnsSdRr {
   std::string name;
   int32_t srv_port;
   std::string srv_target;
   std::string hinfo[2];
   std::string txt;

   /**
    * \brief Constructor.
    */
   DnsSdRr() {
      name = std::string();
      srv_port = -1;
      srv_target = std::string();
      hinfo[0] = std::string();
      txt = std::string();
   }
};

/**
 * \brief Flow record extension header for storing parsed DNSSD packets.
 */
struct RecordExtDNSSD : public RecordExt {
   static int REGISTERED_ID;

   std::list<std::string> queries;
   std::list<DnsSdRr> responses;

   /**
    * \brief Constructor.
    */
   RecordExtDNSSD() : RecordExt(REGISTERED_ID)
   {
   }

   /**
    * \brief Concatenates all collected queries to a single string.
    * \param [in] max_length Size limit for the output string.
    * \return String of semicolon separated queries.
    *
    * The string will allways contain complete entries.
    */
   std::string queries_to_string(size_t max_length) const {
      std::string ret;

      for (auto it = queries.cbegin(); it != queries.cend(); it++) {
         if (max_length == std::string::npos) {
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
   std::string response_to_string(std::list<DnsSdRr>::const_iterator response) const {
      std::stringstream ret;

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
   std::string responses_to_string(size_t max_length) const {
      std::string ret, part;

      for (auto it = responses.cbegin(); it != responses.cend(); it++) {
         if (max_length == std::string::npos) {
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

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_DNSSD_QUERIES, queries_to_string(std::string::npos).c_str());
      ur_set_string(tmplt, record, F_DNSSD_RESPONSES, responses_to_string(std::string::npos).c_str());
   }

   const char *get_unirec_tmplt() const
   {
      return DNSSD_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      std::string queries = queries_to_string(510);
      std::string responses = responses_to_string(510);

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

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_tmplt[] = {
         IPFIX_DNSSD_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };

      return ipfix_tmplt;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "dnssdqueries=\"" << queries_to_string(std::string::npos) << "\""
         << ",dnssdresponses=\"" << responses_to_string(std::string::npos) << "\"";
      return out.str();
   }
};

/**
 * \brief Flow cache plugin for parsing DNSSD packets.
 */
class DNSSDPlugin : public ProcessPlugin
{
public:
   DNSSDPlugin();
   ~DNSSDPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new DNSSDOptParser(); }
   std::string get_name() const { return "dnssd"; }
   RecordExt *get_ext() const { return new RecordExtDNSSD(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void finish(bool print_stats);

private:
   bool txt_all_records;   /**< Indicator whether to process all TXT recods. */
   uint32_t queries;       /**< Total number of parsed DNS queries. */
   uint32_t responses;     /**< Total number of parsed DNS responses. */
   uint32_t total;         /**< Total number of parsed DNS packets. */

   const char *data_begin; /**< Pointer to begin of payload. */
   uint32_t data_len;      /**< Length of packet payload. */

   bool parse_dns(const char *data, unsigned int payload_len, bool tcp, RecordExtDNSSD *rec);
   int  add_ext_dnssd(const char *data, unsigned int payload_len, bool tcp, Flow &rec);
   void process_rdata(const char *record_begin, const char *data, DnsSdRr &rdata, uint16_t type, size_t length) const;
   void filtered_append(RecordExtDNSSD *rec, std::string name);
   void filtered_append(RecordExtDNSSD *rec, std::string name, uint16_t type, DnsSdRr &rdata);

   std::string get_name(const char *data) const;
   size_t get_name_length(const char *data) const;
   const std::string get_service_str(std::string &name) const;

   bool parse_params(const std::string &params, std::string &config_file);
   void load_txtconfig(const char *config_file);
   bool matches_service(std::list<std::pair<std::string, std::list<std::string> > >::const_iterator &it, std::string &name) const;

   std::list<std::pair<std::string, std::list<std::string> > > txt_config;   /**< Configuration for TXT record filter. */
};

}
#endif /* IPXP_PROCESS_DNSSD_HPP */
