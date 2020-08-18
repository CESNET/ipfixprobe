/**
 * \file ntpplugin.h
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

#ifndef NTPPLUGIN_H
#define NTPPLUGIN_H

#include <cstdlib>
#include <iostream>
#include <fields.h>
#include <stdio.h>

#include "flowcacheplugin.h"
#include "flowifc.h"
#include "flow_meter.h"
#include "packet.h"

using namespace std;

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
struct RecordExtNTP : RecordExt {
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
   RecordExtNTP() : RecordExt(ntp)
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

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
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
#endif
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
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
};

/**
 *\brief Flow cache plugin for parsing DNS packets.
 */
class NTPPlugin : public FlowCachePlugin
{
public:
   NTPPlugin(const options_t &module_options);
   NTPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   void finish();
   string get_unirec_field_string();
   const char **get_ipfix_string();

private:
   bool parse_ntp(const Packet &pkt, RecordExtNTP *ntp_data_ext);
   void add_ext_ntp(Flow &rec, const Packet &pkt);
   string parse_timestamp(const Packet &pkt, int p1, int p4, int p5, int p8);

   bool print_stats;    /**< Indicator whether to print stats when flow cache is finishing or not. */
   uint32_t requests;   /**< Total number of parsed NTP queries. */
   uint32_t responses;  /**< Total number of parsed NTP responses. */
   uint32_t total;      /**< Total number of parsed DNS packets. */
};

#endif
