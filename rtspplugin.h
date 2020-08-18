/**
 * \file rtspplugin.h
 * \brief Plugin for parsing RTSP traffic
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

#ifndef RTSPPLUGIN_H
#define RTSPPLUGIN_H

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <fields.h>

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "httpplugin.h"

using namespace std;

/**
 * \brief Flow record extension header for storing RTSP requests.
 */
struct RecordExtRTSP : RecordExt {
   bool req;
   bool resp;

   char method[10];
   char user_agent[128];
   char uri[128];


   uint16_t code;
   char content_type[32];
   char server[128];

   /**
    * \brief Constructor.
    */
   RecordExtRTSP() : RecordExt(rtsp)
   {
      req = false;
      resp = false;

      method[0] = 0;
      user_agent[0] = 0;
      uri[0] = 0;

      code = 0;
      content_type[0] = 0;
      server[0] = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
      ur_set_string(tmplt, record, F_RTSP_REQUEST_METHOD, method);
      ur_set_string(tmplt, record, F_RTSP_REQUEST_AGENT, user_agent);
      ur_set_string(tmplt, record, F_RTSP_REQUEST_URI, uri);

      ur_set(tmplt, record, F_RTSP_RESPONSE_STATUS_CODE, code);
      ur_set_string(tmplt, record, F_RTSP_RESPONSE_SERVER, server);
      ur_set_string(tmplt, record, F_RTSP_RESPONSE_CONTENT_TYPE, content_type);
#endif
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int length, total_length = 0;

      // Method
      length = strlen(method);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, method, length);
      total_length += length + 1;

      // User Agent
      length = strlen(user_agent);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, user_agent, length);
      total_length = length + 1;

      // URI
      length = strlen(uri);
      if (total_length + length + 3 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, uri, length);
      total_length += length + 1;

      // Response code
      *(uint16_t *) (buffer + total_length) = ntohs(code);
      total_length += 2;

      // Server
      length = strlen(server);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, server, length);
      total_length += length + 1;

      // Content type
      length = strlen(content_type);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, content_type, length);
      total_length += length + 1;

      return total_length;
   }
};

/**
 * \brief Flow cache plugin used to parse RTSP requests / responses.
 */
class RTSPPlugin : public FlowCachePlugin
{
public:
   RTSPPlugin(const options_t &module_options);
   RTSPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   ~RTSPPlugin();
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish();
   string get_unirec_field_string();
   const char **get_ipfix_string();

private:
   bool is_response(const char *data, int payload_len);
   bool is_request(const char *data, int payload_len);
   bool parse_rtsp_request(const char *data, int payload_len, RecordExtRTSP *rec);
   bool parse_rtsp_response(const char *data, int payload_len, RecordExtRTSP *rec);
   void add_ext_rtsp_request(const char *data, int payload_len, Flow &flow);
   void add_ext_rtsp_response(const char *data, int payload_len, Flow &flow);
   bool valid_rtsp_method(const char *method) const;

   RecordExtRTSP *recPrealloc;/**< Preallocated extension. */
   bool print_stats;          /**< Print stats when flow cache is finishing. */
   bool flush_flow;           /**< Tell FlowCache to flush current Flow. */
   uint32_t requests;         /**< Total number of parsed RTSP requests. */
   uint32_t responses;        /**< Total number of parsed RTSP responses. */
   uint32_t total;            /**< Total number of parsed RTSP packets. */
};

#endif
