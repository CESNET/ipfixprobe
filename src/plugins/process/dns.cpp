/**
 * \file dns.cpp
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

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "dns.hpp"

namespace ipxp {

int RecordExtDNS::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("dns", [](){return new DNSPlugin();});
   register_plugin(&rec);
   RecordExtDNS::REGISTERED_ID = register_extension();
}

//#define DEBUG_DNS

// Print debug message if debugging is allowed.
#ifdef DEBUG_DNS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_DNS
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

DNSPlugin::DNSPlugin() : queries(0), responses(0), total(0), data_begin(nullptr), data_len(0)
{
}

DNSPlugin::~DNSPlugin()
{
   close();
}

void DNSPlugin::init(const char *params)
{
}

void DNSPlugin::close()
{
}

ProcessPlugin *DNSPlugin::copy()
{
   return new DNSPlugin(*this);
}

int DNSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (pkt.dst_port == 53 || pkt.src_port == 53) {
      return add_ext_dns(reinterpret_cast<const char *>(pkt.payload), pkt.payload_len, pkt.ip_proto == IPPROTO_TCP, rec);
   }

   return 0;
}

int DNSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   if (pkt.dst_port == 53 || pkt.src_port == 53) {
      RecordExt *ext = rec.get_extension(RecordExtDNS::REGISTERED_ID);
      if (ext == nullptr) {
         return add_ext_dns(reinterpret_cast<const char *>(pkt.payload), pkt.payload_len, pkt.ip_proto == IPPROTO_TCP, rec);
      } else {
         parse_dns(reinterpret_cast<const char *>(pkt.payload), pkt.payload_len, pkt.ip_proto == IPPROTO_TCP, static_cast<RecordExtDNS *>(ext));
      }
      return FLOW_FLUSH;
   }

   return 0;
}

void DNSPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "DNS plugin stats:" << std::endl;
      std::cout << "   Parsed dns queries: " << queries << std::endl;
      std::cout << "   Parsed dns responses: " << responses << std::endl;
      std::cout << "   Total dns packets processed: " << total << std::endl;
   }
}

/**
 * \brief Get name length.
 * \param [in] data Pointer to string.
 * \return Number of characters in string.
 */
size_t DNSPlugin::get_name_length(const char *data) const
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
std::string DNSPlugin::get_name(const char *data) const
{
   std::string name = "";
   int label_cnt = 0;

   if ((uint32_t) (data - data_begin) > data_len) {
      throw "Error: overflow";
   }

   while (data[0]) { /* Check for terminating character. */
      if (IS_POINTER(data[0])) { /* Check for label pointer (11xxxxxx byte) */
         data = data_begin + GET_OFFSET(data[0], data[1]);

         /* Check for possible errors.*/
         if (label_cnt++ > MAX_LABEL_CNT || (uint32_t) (data - data_begin) > data_len) {
            throw "Error: label count exceed or overflow";
         }

         continue;
      }

      /* Check for possible errors.*/
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
 * \brief Process SRV strings.
 * \param [in,out] str Raw SRV string.
 */
void DNSPlugin::process_srv(std::string &str) const
{
   bool underline_found = false;
   for (int i = 0; str[i]; i++) {
      if (str[i] == '_') {
         str.erase(i--, 1);
         if (underline_found) {
            break;
         }
         underline_found = true;
      }
   }
   size_t pos = str.find('.');
   if (pos != std::string::npos) {
      str[pos] = ' ';

      pos = str.find('.', pos);
      if (pos != std::string::npos) {
         str[pos] = ' ';
      }
   }
}

/**
 * \brief Process RDATA section.
 * \param [in] record_begin Pointer to start of current resource record.
 * \param [in] data Pointer to RDATA section.
 * \param [out] rdata String which stores processed data.
 * \param [in] type Type of RDATA section.
 * \param [in] length Length of RDATA section.
 */
void DNSPlugin::process_rdata(const char *record_begin, const char *data, std::ostringstream &rdata, uint16_t type, size_t length) const
{
   rdata.str("");
   rdata.clear();

   switch (type){
   case DNS_TYPE_A:
      rdata << inet_ntoa(*(struct in_addr *) (data));
      DEBUG_MSG("\tData A:\t\t\t%s\n",       rdata.str().c_str());
      break;
   case DNS_TYPE_AAAA:
      {
         char addr[INET6_ADDRSTRLEN];
         inet_ntop(AF_INET6, (const void *) data, addr, INET6_ADDRSTRLEN);
         rdata << addr;
         DEBUG_MSG("\tData AAAA:\t\t%s\n",   rdata.str().c_str());
      }
      break;
   case DNS_TYPE_NS:
      rdata << get_name(data);
      DEBUG_MSG("\tData NS:\t\t\t%s\n",      rdata.str().c_str());
      break;
   case DNS_TYPE_CNAME:
      rdata << get_name(data);
      DEBUG_MSG("\tData CNAME:\t\t%s\n",     rdata.str().c_str());
      break;
   case DNS_TYPE_PTR:
      rdata << get_name(data);
      DEBUG_MSG("\tData PTR:\t\t%s\n",       rdata.str().c_str());
      break;
   case DNS_TYPE_DNAME:
      rdata << get_name(data);
      DEBUG_MSG("\tData DNAME:\t\t%s\n",     rdata.str().c_str());
      break;
   case DNS_TYPE_SOA:
      {
         rdata << get_name(data);
         data += get_name_length(data);
         std::string tmp = get_name(data);
         data += get_name_length(data);

         DEBUG_MSG("\t\tMName:\t\t%s\n",     rdata.str().c_str());
         DEBUG_MSG("\t\tRName:\t\t%s\n",     tmp.c_str());

         rdata << " " << tmp;

         struct dns_soa *soa = (struct dns_soa *) data;
         DEBUG_MSG("\t\tSerial:\t\t%u\n",    ntohl(soa->serial));
         DEBUG_MSG("\t\tRefresh:\t%u\n",     ntohl(soa->refresh));
         DEBUG_MSG("\t\tRetry:\t\t%u\n",     ntohl(soa->retry));
         DEBUG_MSG("\t\tExpiration:\t%u\n",  ntohl(soa->expiration));
         DEBUG_MSG("\t\tMin TTL:\t%u\n",     ntohl(soa->ttl));
         rdata << " " << ntohl(soa->serial) << " " << ntohl(soa->refresh) << " "
               << ntohl(soa->retry) << " " << ntohl(soa->expiration) << " " << ntohl(soa->ttl);
      }
      break;
   case DNS_TYPE_SRV:
      {
         DEBUG_MSG("\tData SRV:\n");
         std::string tmp = get_name(record_begin);
         process_srv(tmp);
         struct dns_srv *srv = (struct dns_srv *) data;

         DEBUG_MSG("\t\tPriority:\t%u\n",    ntohs(srv->priority));
         DEBUG_MSG("\t\tWeight:\t\t%u\n",    ntohs(srv->weight));
         DEBUG_MSG("\t\tPort:\t\t%u\n",      ntohs(srv->port));

         rdata << tmp << " ";
         tmp = get_name(data + 6);

         DEBUG_MSG("\t\tTarget:\t\t%s\n", tmp.c_str());
         rdata << tmp << " " << ntohs(srv->priority) << " " <<  ntohs(srv->weight) << " " << ntohs(srv->port);
      }
      break;
   case DNS_TYPE_MX:
      {
         uint16_t preference = ntohs(*(uint16_t *) data);
         rdata << preference << " " << get_name(data + 2);
         DEBUG_MSG("\tData MX:\n");
         DEBUG_MSG("\t\tPreference:\t%u\n",     preference);
         DEBUG_MSG("\t\tMail exchanger:\t%s\n", get_name(data + 2).c_str());
      }
      break;
   case DNS_TYPE_TXT:
      {
         DEBUG_MSG("\tData TXT:\n");

         size_t len = (uint8_t) *(data++);
         size_t total_len = len + 1;

         while (length != 0 && total_len <= length) {
            DEBUG_MSG("\t\tTXT data:\t%s\n",    std::string(data, len).c_str());
            rdata << std::string(data, len);

            data += len;
            len = (uint8_t) *(data++);
            total_len += len + 1;

            if (total_len <= length) {
               rdata << " ";
            }
         }
      }
      break;
   case DNS_TYPE_MINFO:
      DEBUG_MSG("\tData MINFO:\n");
      rdata << get_name(data);
      DEBUG_MSG("\t\tRMAILBX:\t%s\n",  rdata.str().c_str());
      data += get_name_length(data);

      rdata << get_name(data);
      DEBUG_MSG("\t\tEMAILBX:\t%s\n",  get_name(data).c_str());
      break;
   case DNS_TYPE_HINFO:
      DEBUG_MSG("\tData HINFO:\n");
      rdata << std::string(data, length);
      DEBUG_MSG("\t\tData:\t%s\n", rdata.str().c_str());
      break;
   case DNS_TYPE_ISDN:
      DEBUG_MSG("\tData ISDN:\n");
      rdata << std::string(data, length);
      DEBUG_MSG("\t\tData:\t%s\n", rdata.str().c_str());
      break;
   case DNS_TYPE_DS:
      {
         struct dns_ds *ds = (struct dns_ds *) data;
         DEBUG_MSG("\tData DS:\n");
         DEBUG_MSG("\t\tKey tag:\t%u\n",        ntohs(ds->keytag));
         DEBUG_MSG("\t\tAlgorithm:\t%u\n",      ds->algorithm);
         DEBUG_MSG("\t\tDigest type:\t%u\n",    ds->digest_type);
         DEBUG_MSG("\t\tDigest:\t\t(binary)\n");
         rdata << ntohs(ds->keytag) << " " << (uint16_t) ds->keytag << " "
               << (uint16_t) ds->digest_type << " <key>";
      }
      break;
   case DNS_TYPE_RRSIG:
      {
         struct dns_rrsig *rrsig = (struct dns_rrsig *) data;
         std::string tmp = "";
         DEBUG_MSG("\tData RRSIG:\n");
         DEBUG_MSG("\t\tType:\t\t%u\n",         ntohs(rrsig->type));
         DEBUG_MSG("\t\tAlgorithm:\t%u\n",      rrsig->algorithm);
         DEBUG_MSG("\t\tLabels:\t\t%u\n",       rrsig->labels);
         DEBUG_MSG("\t\tTTL:\t\t%u\n",          ntohl(rrsig->ttl));
         DEBUG_MSG("\t\tSig expiration:\t%u\n", ntohl(rrsig->sig_expiration));
         DEBUG_MSG("\t\tSig inception:\t%u\n",  ntohl(rrsig->sig_inception));
         DEBUG_MSG("\t\tKey tag:\t%u\n",        ntohs(rrsig->keytag));
         rdata << ntohs(rrsig->type) << " " << (uint16_t) rrsig->algorithm << " " // Conversion needed, otherwise uint8_t will be threated as a char.
               << (uint16_t) rrsig->labels << " " << ntohl(rrsig->ttl) << " "
               << ntohl(rrsig->sig_expiration) << " " << ntohl(rrsig->sig_inception)
               << " " << ntohs(rrsig->keytag) << " <key>";

         tmp = get_name(data + 18);
         DEBUG_MSG("\t\tSigner's name:\t%s\n",  tmp.c_str());
         DEBUG_MSG("\t\tSignature:\t(binary)\n");
      }
      break;
   case DNS_TYPE_DNSKEY:
      {
         struct dns_dnskey *dnskey = (struct dns_dnskey *) data;
         DEBUG_MSG("\tData DNSKEY:\n");
         DEBUG_MSG("\t\tFlags:\t\t%u\n",        ntohs(dnskey->flags));
         DEBUG_MSG("\t\tProtocol:\t%u\n",       dnskey->protocol);
         DEBUG_MSG("\t\tAlgorithm:\t%u\n",      dnskey->algorithm);

         rdata << ntohs(dnskey->flags) << " " << (uint16_t) dnskey->protocol << " " << (uint16_t) dnskey->algorithm << " <key>";
         DEBUG_MSG("\t\tPublic key:\t(binary data)\n");
      }
      break;
   default:
      DEBUG_MSG("\tData:\t\t\t(format not supported yet)\n");
      rdata << "(not_impl)";
      break;
   }
}

#ifdef DEBUG_DNS
uint32_t s_queries = 0;
uint32_t s_responses = 0;
#endif /* DEBUG_DNS */

/**
 * \brief Parse and store DNS packet.
 * \param [in] data Pointer to packet payload section.
 * \param [in] payload_len Payload length.
 * \param [in] tcp DNS over tcp.
 * \param [out] rec Output Flow extension header.
 * \return True if DNS was parsed.
 */
bool DNSPlugin::parse_dns(const char *data, unsigned int payload_len, bool tcp, RecordExtDNS *rec)
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

      rec->answers = answer_rr_cnt;
      rec->id = ntohs(dns->id);
      rec->rcode = DNS_HDR_GET_RESPCODE(flags);

      DEBUG_MSG("%s number: %u\n",                    DNS_HDR_GET_QR(flags) ? "Response" : "Query",
                                                      DNS_HDR_GET_QR(flags) ? s_queries++ : s_responses++);
      DEBUG_MSG("DNS message header\n");
      DEBUG_MSG("\tTransaction ID:\t\t%#06x\n",       ntohs(dns->id));
      DEBUG_MSG("\tFlags:\t\t\t%#06x\n",              ntohs(dns->flags));

      DEBUG_MSG("\t\tQuestion/reply:\t\t%u\n",        DNS_HDR_GET_QR(flags));
      DEBUG_MSG("\t\tOP code:\t\t%u\n",               DNS_HDR_GET_OPCODE(flags));
      DEBUG_MSG("\t\tAuthoritative answer:\t%u\n",    DNS_HDR_GET_AA(flags));
      DEBUG_MSG("\t\tTruncation:\t\t%u\n",            DNS_HDR_GET_TC(flags));
      DEBUG_MSG("\t\tRecursion desired:\t%u\n",       DNS_HDR_GET_RD(flags));
      DEBUG_MSG("\t\tRecursion available:\t%u\n",     DNS_HDR_GET_RA(flags));
      DEBUG_MSG("\t\tReserved:\t\t%u\n",              DNS_HDR_GET_Z(flags));
      DEBUG_MSG("\t\tAuth data:\t\t%u\n",             DNS_HDR_GET_AD(flags));
      DEBUG_MSG("\t\tChecking disabled:\t%u\n",       DNS_HDR_GET_CD(flags));
      DEBUG_MSG("\t\tResponse code:\t\t%u\n",         DNS_HDR_GET_RESPCODE(flags));

      DEBUG_MSG("\tQuestions:\t\t%u\n",               question_cnt);
      DEBUG_MSG("\tAnswer RRs:\t\t%u\n",              answer_rr_cnt);
      DEBUG_MSG("\tAuthority RRs:\t\t%u\n",           authority_rr_cnt);
      DEBUG_MSG("\tAdditional RRs:\t\t%u\n",          additional_rr_cnt);

      /********************************************************************
      *****                   DNS Question section                    *****
      ********************************************************************/
      data += sizeof(struct dns_hdr);
      for (int i = 0; i < question_cnt; i++) {
         DEBUG_MSG("\nDNS question #%d\n",            i + 1);
         std::string name = get_name(data);
         DEBUG_MSG("\tName:\t\t\t%s\n",               name.c_str());

         data += get_name_length(data);
         struct dns_question *question = (struct dns_question *) data;

         if ((data - data_begin) + sizeof(struct dns_question) > payload_len) {
            DEBUG_MSG("DNS parser quits: overflow\n\n");
            return 1;
         }

         if (i == 0) { // Copy only first question.
            rec->qtype = ntohs(question->qtype);
            rec->qclass = ntohs(question->qclass);

            size_t length = name.length();
            if (length >= sizeof(rec->qname)) {
               DEBUG_MSG("Truncating qname (length = %lu) to %lu.\n", length, sizeof(rec->qname) - 1);
               length = sizeof(rec->qname) - 1;
            }
            memcpy(rec->qname, name.c_str(), length);
            rec->qname[length] = 0;
         }
         DEBUG_MSG("\tType:\t\t\t%u\n",               ntohs(question->qtype));
         DEBUG_MSG("\tClass:\t\t\t%u\n",              ntohs(question->qclass));
         data += sizeof(struct dns_question);
      }

      /********************************************************************
      *****                    DNS Answers section                    *****
      ********************************************************************/
      const char *record_begin;
      size_t rdlength;
      std::ostringstream rdata;
      for (int i = 0; i < answer_rr_cnt; i++) { // Process answers section.
         record_begin = data;

         DEBUG_MSG("DNS answer #%d\n", i + 1);
         DEBUG_MSG("\tAnswer name:\t\t%s\n",          get_name(data).c_str());
         data += get_name_length(data);

         struct dns_answer *answer = (struct dns_answer *) data;

         uint32_t tmp = (data - data_begin) + sizeof(dns_answer);
         if (tmp > payload_len || tmp + ntohs(answer->rdlength) > payload_len) {
            DEBUG_MSG("DNS parser quits: overflow\n\n");
            return 1;
         }

         DEBUG_MSG("\tType:\t\t\t%u\n",               ntohs(answer->atype));
         DEBUG_MSG("\tClass:\t\t\t%u\n",              ntohs(answer->aclass));
         DEBUG_MSG("\tTTL:\t\t\t%u\n",                ntohl(answer->ttl));
         DEBUG_MSG("\tRD length:\t\t%u\n",            ntohs(answer->rdlength));

         data += sizeof(struct dns_answer);
         rdlength = ntohs(answer->rdlength);

         if (i == 0) { // Copy only first answer.
            process_rdata(record_begin, data, rdata, ntohs(answer->atype), rdlength);
            rec->rr_ttl = ntohl(answer->ttl);

            size_t length = rdata.str().length();
            if (length >= sizeof(rec->data)) {
               DEBUG_MSG("Truncating rdata (length = %lu) to %lu.\n", length, sizeof(rec->data) - 1);
               length = sizeof(rec->data) - 1;
            }
            memcpy(rec->data, rdata.str().c_str(), length); // Copy processed rdata.
            rec->data[length] = 0; // Add terminating '\0' char.
            rec->rlength = length; // Report length.
         }
         data += rdlength;
      }

      /********************************************************************
      *****                 DNS Authority RRs section                 *****
      ********************************************************************/

      for (int i = 0; i < authority_rr_cnt; i++) { // Unused yet.
         record_begin = data;

         DEBUG_MSG("DNS authority RR #%d\n", i + 1);
         DEBUG_MSG("\tAnswer name:\t\t%s\n",          get_name(data).c_str());
         data += get_name_length(data);

         struct dns_answer *answer = (struct dns_answer *) data;

         uint32_t tmp = (data - data_begin) + sizeof(dns_answer);
         if (tmp > payload_len || tmp + ntohs(answer->rdlength) > payload_len) {
            DEBUG_MSG("DNS parser quits: overflow\n\n");
            return 1;
         }

         DEBUG_MSG("\tType:\t\t\t%u\n",               ntohs(answer->atype));
         DEBUG_MSG("\tClass:\t\t\t%u\n",              ntohs(answer->aclass));
         DEBUG_MSG("\tTTL:\t\t\t%u\n",                ntohl(answer->ttl));
         DEBUG_MSG("\tRD length:\t\t%u\n",            ntohs(answer->rdlength));

         data += sizeof(struct dns_answer);
         rdlength = ntohs(answer->rdlength);
         DEBUG_CODE(process_rdata(record_begin, data, rdata, ntohs(answer->atype), rdlength));

         data += rdlength;
      }

      /********************************************************************
      *****                 DNS Additional RRs section                *****
      ********************************************************************/
      for (int i = 0; i < additional_rr_cnt; i++) { // Unused yet.
         record_begin = data;

         DEBUG_MSG("DNS additional RR #%d\n", i + 1);
         DEBUG_MSG("\tAnswer name:\t\t%s\n",          get_name(data).c_str());
         data += get_name_length(data);

         struct dns_answer *answer = (struct dns_answer *) data;

         uint32_t tmp = (data - data_begin) + sizeof(dns_answer);
         if (tmp > payload_len || tmp + ntohs(answer->rdlength) > payload_len) {
            DEBUG_MSG("DNS parser quits: overflow\n\n");
            return 1;
         }

         DEBUG_MSG("\tType:\t\t\t%u\n",               ntohs(answer->atype));
         if (ntohs(answer->atype) != DNS_TYPE_OPT) {
            DEBUG_MSG("\tClass:\t\t\t%u\n",           ntohs(answer->aclass));
            DEBUG_MSG("\tTTL:\t\t\t%u\n",             ntohl(answer->ttl));
            DEBUG_MSG("\tRD length:\t\t%u\n",         ntohs(answer->rdlength));

            data += sizeof(struct dns_answer);
            rdlength = ntohs(answer->rdlength);
            DEBUG_CODE(process_rdata(record_begin, data, rdata, ntohs(answer->atype), rdlength));
         } else { // Process OPT record.
            DEBUG_MSG("\tReq UDP payload:\t%u\n",     ntohs(answer->aclass));
            DEBUG_CODE(uint32_t ttl = ntohl(answer->ttl));
            DEBUG_MSG("\tExtended RCODE:\t\t%#x\n",   (ttl & 0xFF000000) >> 24);
            DEBUG_MSG("\tVersion:\t\t%#x\n",          (ttl & 0x00FF0000) >> 16);
            DEBUG_MSG("\tDO bit:\t\t\t%u\n",          ((ttl & 0x8000) >> 15));
            DEBUG_MSG("\tReserved:\t\t%u\n",          (ttl & 0x7FFF));
            DEBUG_MSG("\tRD length:\t\t%u\n",         ntohs(answer->rdlength));

            data += sizeof(struct dns_answer);
            rdlength = ntohs(answer->rdlength);
            rec->psize = ntohs(answer->aclass); // Copy requested UDP payload size. RFC 6891
            rec->dns_do = ((ntohl(answer->ttl) & 0x8000) >> 15); // Copy DO bit.
         }

         data += rdlength;
      }

      if (DNS_HDR_GET_QR(flags)) {
         responses++;
      } else {
         queries++;
      }

      DEBUG_MSG("DNS parser quits: parsing done\n\n");
   } catch (const char *err) {
      DEBUG_MSG("%s\n", err);
      return false;
   }

   return true;
}

/**
 * \brief Add new extension DNS header into Flow.
 * \param [in] data Pointer to packet payload section.
 * \param [in] payload_len Payload length.
 * \param [in] tcp DNS over tcp.
 * \param [out] rec Destination Flow.
 */
int DNSPlugin::add_ext_dns(const char *data, unsigned int payload_len, bool tcp, Flow &rec)
{
   RecordExtDNS *ext = new RecordExtDNS();
   if (!parse_dns(data, payload_len, tcp, ext)) {
      delete ext;
      return 0;
   } else {
      rec.add_extension(ext);
   }
   return FLOW_FLUSH;
}

}
