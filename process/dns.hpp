/**
 * \file dns.hpp
 * \brief Plugin for parsing DNS traffic.
 * \author Jiri Havranek <havranek@cesnet.cz>
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
 *
 *
 */

#ifndef IPXP_PROCESS_DNS_HPP
#define IPXP_PROCESS_DNS_HPP

#include <string>
#include <cstring>
#include <sstream>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include "dns-utils.hpp"

namespace ipxp {

#define DNS_UNIREC_TEMPLATE "DNS_ID,DNS_ANSWERS,DNS_RCODE,DNS_NAME,DNS_QTYPE,DNS_CLASS,DNS_RR_TTL,DNS_RLENGTH,DNS_RDATA,DNS_PSIZE,DNS_DO"

UR_FIELDS (
   uint16 DNS_ID,
   uint16 DNS_ANSWERS,
   uint8  DNS_RCODE,
   string DNS_NAME,
   uint16 DNS_QTYPE,
   uint16 DNS_CLASS,
   uint32 DNS_RR_TTL,
   uint16 DNS_RLENGTH,
   bytes DNS_RDATA,

   uint16 DNS_PSIZE,
   uint8  DNS_DO
)

/**
 * \brief Flow record extension header for storing parsed DNS packets.
 */
struct RecordExtDNS : public RecordExt {
   static int REGISTERED_ID;

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
   RecordExtDNS() : RecordExt(REGISTERED_ID)
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

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
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
   }

   const char *get_unirec_tmplt() const
   {
      return DNS_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
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

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_tmplt[] = {
         IPFIX_DNS_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };
      return ipfix_tmplt;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "dnsid=" << id
         << ",answers=" << answers
         << ",rcode=" << rcode
         << ",qname=\"" << qname << "\""
         << ",qtype=" << qtype
         << ",qclass=" << qclass
         << ",rrttl=" << rr_ttl
         << ",rlength=" << rlength
         << ",data=\"" << data << "\""
         << ",psize=" << psize
         << ",dnsdo=" << dns_do;
      return out.str();
   }
};

/**
 * \brief Flow cache plugin for parsing DNS packets.
 */
class DNSPlugin : public ProcessPlugin
{
public:
   DNSPlugin();
   ~DNSPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("dns", "Parse DNS packets"); }
   std::string get_name() const { return "dns"; }
   RecordExt *get_ext() const { return new RecordExtDNS(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void finish(bool print_stats);

private:
   uint32_t queries;       /**< Total number of parsed DNS queries. */
   uint32_t responses;     /**< Total number of parsed DNS responses. */
   uint32_t total;         /**< Total number of parsed DNS packets. */

   const char *data_begin; /**< Pointer to begin of payload. */
   uint32_t data_len;      /**< Length of packet payload. */

   bool parse_dns(const char *data, unsigned int payload_len, bool tcp, RecordExtDNS *rec);
   int  add_ext_dns(const char *data, unsigned int payload_len, bool tcp, Flow &rec);
   void process_srv(std::string &str) const;
   void process_rdata(const char *record_begin, const char *data, std::ostringstream &rdata, uint16_t type, size_t length) const;

   std::string get_name(const char *data) const;
   size_t get_name_length(const char *data) const;
};

}
#endif /* IPXP_PROCESS_DNS_HPP */
