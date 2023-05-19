/**
 * \file ntp.hpp
 * \author Alejandro Robledo <robleale@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
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

#ifndef IPXP_PROCESS_NTP_HPP
#define IPXP_PROCESS_NTP_HPP

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

#ifdef WITH_NEMEA
#include <fields.h>
#endif

#include <stdio.h>

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define NTP_UNIREC_TEMPLATE  "NTP_LEAP,NTP_VERSION,NTP_MODE,NTP_STRATUM,NTP_POLL,NTP_PRECISION,NTP_DELAY,NTP_DISPERSION,NTP_REF_ID,NTP_REF,NTP_ORIG,NTP_RECV,NTP_SENT"

UR_FIELDS (
   uint8 NTP_LEAP,
   uint8 NTP_VERSION
   uint8 NTP_MODE,
   uint8 NTP_STRATUM,
   uint8 NTP_POLL,
   uint8 NTP_PRECISION,
   uint32 NTP_DELAY,
   uint32 NTP_DISPERSION,
   string NTP_REF_ID,
   string NTP_REF,
   string NTP_ORIG,
   string NTP_RECV,
   string NTP_SENT
)

#define NTP_FIELD_IP 16
#define NTP_FIELD_LEN64 30

const char NTP_RefID_INIT[] = "73.78.73.84"; /*Value of NTP reference ID INIT*/
const char INIT[] = "INIT";
const char NTP_RefID_STEP[] = "83.84.69.80"; /*Value of NTP reference ID STEP*/
const char STEP[] = "STEP";
const char NTP_RefID_DENY[] = "68.69.78.89"; /*Value of NTP reference ID DENY*/
const char DENY[] = "DENY";
const char NTP_RefID_RATE[] = "82.65.84.69"; /*Value of NTP reference ID RATE*/
const char RATE[] = "RATE";
const char OTHER[] = "OTHER"; /*OTHER Value of NTP reference ID*/

/**
 *\brief Flow record extension header for storing NTP fields.
 */
struct RecordExtNTP : public RecordExt {
   static int REGISTERED_ID;

   uint8_t leap;
   uint8_t version;
   uint8_t mode;
   uint8_t stratum;
   uint8_t poll;
   uint8_t precision;
   uint32_t delay;
   uint32_t dispersion;
   char reference_id[NTP_FIELD_IP];
   char reference[NTP_FIELD_LEN64];
   char origin[NTP_FIELD_LEN64];
   char receive[NTP_FIELD_LEN64];
   char sent[NTP_FIELD_LEN64];

   /**
         *\brief Constructor.
   */
   RecordExtNTP() : RecordExt(REGISTERED_ID)
   {
      leap = 9;
      version = 9;
      mode = 9;
      stratum = 9;
      poll = 9;
      precision = 9;
      delay = 9;
      dispersion = 9;
      reference_id[0] = 9;
      reference[0] = 9;
      origin[0] = 9;
      receive[0] = 9;
      sent[0] = 9;
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_NTP_LEAP, leap);
      ur_set(tmplt, record, F_NTP_VERSION, version);
      ur_set(tmplt, record, F_NTP_MODE, mode);
      ur_set(tmplt, record, F_NTP_STRATUM, stratum);
      ur_set(tmplt, record, F_NTP_POLL, poll);
      ur_set(tmplt, record, F_NTP_PRECISION, precision);
      ur_set(tmplt, record, F_NTP_DELAY, delay);
      ur_set(tmplt, record, F_NTP_DISPERSION, dispersion);
      ur_set_string(tmplt, record, F_NTP_REF_ID, reference_id);
      ur_set_string(tmplt, record, F_NTP_REF, reference);
      ur_set_string(tmplt, record, F_NTP_ORIG, origin);
      ur_set_string(tmplt, record, F_NTP_RECV, receive);
      ur_set_string(tmplt, record, F_NTP_SENT, sent);
   }

   const char *get_unirec_tmplt() const
   {
      return NTP_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      int length, total_length = 14;

      if (total_length > size) {
         return -1;
      }
      *(uint8_t *) (buffer) = leap;
      *(uint8_t *) (buffer + 1) = version;
      *(uint8_t *) (buffer + 2) = mode;
      *(uint8_t *) (buffer + 3) = stratum;
      *(uint8_t *) (buffer + 4) = poll;
      *(uint8_t *) (buffer + 5) = precision;
      *(uint32_t *) (buffer + 6) = ntohl(delay);
      *(uint32_t *) (buffer + 10) = ntohl(dispersion);

      length = strlen(reference_id);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, reference_id, length);
      total_length += length + 1;

      length = strlen(reference);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, reference, length);
      total_length += length + 1;

      length = strlen(origin);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, origin, length);
      total_length += length + 1;

      length = strlen(receive);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, receive, length);
      total_length += length + 1;

      length = strlen(sent);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, sent, length);
      total_length += length + 1;

      return total_length;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_tmplt[] = {
         IPFIX_NTP_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };

      return ipfix_tmplt;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "leap=" << (uint16_t) leap
         << ",version=" << (uint16_t) version
         << ",mode=" << (uint16_t) mode
         << ",stratum=" << (uint16_t) stratum
         << ",poll=" << (uint16_t) poll
         << ",precision=" << (uint16_t) precision
         << ",delay=" << delay
         << ",dispersion=" << dispersion
         << ",referenceid=\"" << reference_id << "\""
         << ",reference=\"" << reference << "\""
         << ",origin=\"" << origin << "\""
         << ",receive=\"" << receive << "\""
         << ",sent=\"" << sent << "\"";
      return out.str();
   }
};

/**
 *\brief Flow cache plugin for parsing DNS packets.
 */
class NTPPlugin : public ProcessPlugin
{
public:
   NTPPlugin();
   ~NTPPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("ntp", "Parse NTP traffic"); }
   std::string get_name() const { return "ntp"; }
   RecordExt *get_ext() const { return new RecordExtNTP(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   void finish(bool print_stats);

private:
   uint32_t requests;   /**< Total number of parsed NTP queries. */
   uint32_t responses;  /**< Total number of parsed NTP responses. */
   uint32_t total;      /**< Total number of parsed DNS packets. */

   bool parse_ntp(const Packet &pkt, RecordExtNTP *ntp_data_ext);
   void add_ext_ntp(Flow &rec, const Packet &pkt);
   std::string parse_timestamp(const Packet &pkt, uint16_t p1, uint16_t p4, uint16_t p5, uint16_t p8);
};

}
#endif /* IPXP_PROCESS_NTP_HPP */
