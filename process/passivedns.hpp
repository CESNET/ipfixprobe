/**
 * \file passivedns.h
 * \brief Plugin for exporting DNS A and AAAA records.
 * \author Jiri Havranek <havranek@cesnet.cz>
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
 *
 *
 */

#ifndef IPXP_PROCESS_PASSIVEDNS_HPP
#define IPXP_PROCESS_PASSIVEDNS_HPP

#include <config.h>
#include <string>
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

#define DNS_UNIREC_TEMPLATE "DNS_ID,DNS_ATYPE,DNS_NAME,DNS_RR_TTL,DNS_IP"

UR_FIELDS (
   uint16 DNS_ID,
   uint16 DNS_ATYPE,
   string DNS_NAME,
   uint32 DNS_RR_TTL,
   ipaddr DNS_IP
)

/**
 * \brief Flow record extension header for storing parsed DNS packets.
 */
struct RecordExtPassiveDNS : public RecordExt {
   static int REGISTERED_ID;
   uint16_t atype;
   uint16_t id;
   uint8_t ip_version;
   char aname[255];
   uint32_t rr_ttl;
   ipaddr_t ip;

   /**
    * \brief Constructor.
    */
   RecordExtPassiveDNS() : RecordExt(REGISTERED_ID)
   {
      id = 0;
      atype = 0;
      ip_version = 0;
      aname[0] = 0;
      rr_ttl = 0;
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_DNS_ID, id);
      ur_set(tmplt, record, F_DNS_ATYPE, atype);
      ur_set_string(tmplt, record, F_DNS_NAME, aname);
      ur_set(tmplt, record, F_DNS_RR_TTL, rr_ttl);
      if (ip_version == 4) {
         ur_set(tmplt, record, F_DNS_IP, ip_from_4_bytes_be((char *) &ip.v4));
      } else if (ip_version == 6) {
         ur_set(tmplt, record, F_DNS_IP, ip_from_16_bytes_be((char *) ip.v6));
      }
   }

   const char *get_unirec_tmplt() const
   {
      return DNS_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
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

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_tmplt[] = {
         IPFIX_PASSIVEDNS_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };

      return ipfix_tmplt;
   }

   std::string get_text() const
   {
      char ip_str[INET6_ADDRSTRLEN];
      std::ostringstream out;

      if (ip_version == 4) {
         inet_ntop(AF_INET, (const void *) &ip.v4, ip_str, INET6_ADDRSTRLEN);
      } else if (ip_version == 6) {
         inet_ntop(AF_INET6, (const void *) &ip.v6, ip_str, INET6_ADDRSTRLEN);
      }

      out << "dnsid=" << id
         << ",atype=" << atype
         << ",aname=\"" << aname << "\""
         << ",rrttl=" << rr_ttl
         << ",ip=" << ip_str;
      return out.str();
   }
};

/**
 * \brief Flow cache plugin for parsing DNS packets.
 */
class PassiveDNSPlugin : public ProcessPlugin
{
public:
   PassiveDNSPlugin();
   ~PassiveDNSPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("passivedns", "Parse A, AAAA and PTR records from DNS traffic"); }
   std::string get_name() const { return "passivedns"; }
   RecordExt *get_ext() const { return new RecordExtPassiveDNS(); }
   ProcessPlugin *copy();
   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void finish(bool print_stats);

private:
   uint32_t total;         /**< Total number of parsed DNS responses. */
   uint32_t parsed_a;      /**< Number of parsed A records. */
   uint32_t parsed_aaaa;   /**< Number of parsed AAAA records. */
   uint32_t parsed_ptr;    /**< Number of parsed PTR records. */

   const char *data_begin; /**< Pointer to begin of payload. */
   uint32_t data_len;      /**< Length of packet payload. */

   RecordExtPassiveDNS *parse_dns(const char *data, unsigned int payload_len, bool tcp);
   int add_ext_dns(const char *data, unsigned int payload_len, bool tcp, Flow &rec);

   std::string get_name(const char *data) const;
   size_t get_name_length(const char *data) const;
   bool process_ptr_record(std::string name, RecordExtPassiveDNS *rec);
   bool str_to_uint4(std::string str, uint8_t &dst);
};

}
#endif /* IPXP_PROCESS_PASSIVEDNS_HPP */
