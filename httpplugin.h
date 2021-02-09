/**
 * \file httpplugin.h
 * \brief Plugin for parsing HTTP traffic
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

#ifndef HTTPPLUGIN_H
#define HTTPPLUGIN_H

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"

using namespace std;

void copy_str(char *dst, ssize_t size, const char *begin, const char *end);

/**
 * \brief Flow record extension header for storing HTTP requests.
 */
struct RecordExtHTTP : RecordExt {
   bool req;
   bool resp;

   char method[10];
   char host[64];
   char uri[128];
   char user_agent[128];
   char referer[128];

   uint16_t code;
   char content_type[32];

   /**
    * \brief Constructor.
    */
   RecordExtHTTP() : RecordExt(http)
   {
      req = false;
      resp = false;
      method[0] = 0;
      host[0] = 0;
      uri[0] = 0;
      user_agent[0] = 0;
      referer[0] = 0;
      code = 0;
      content_type[0] = 0;
   }

#ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_HTTP_REQUEST_METHOD, method);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_HOST, host);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_URL, uri);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_AGENT, user_agent);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_REFERER, referer);
      ur_set_string(tmplt, record, F_HTTP_RESPONSE_CONTENT_TYPE, content_type);
      ur_set(tmplt, record, F_HTTP_RESPONSE_STATUS_CODE, code);
   }
#endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int length, total_length = 0;

      length = strlen(user_agent);
      if (length + 1 > size) {
         return -1;
      }
      buffer[0] = length;
      memcpy(buffer + 1, user_agent, length);
      total_length = length + 1;

      length = strlen(method);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, method, length);
      total_length += length + 1;

      length = strlen(host);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, host, length);
      total_length += length + 1;

      length = strlen(referer);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, referer, length);
      total_length += length + 1;

      length = strlen(uri);
      if (total_length + length + 4 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, uri, length);
      total_length += length + 1;

      length = strlen(content_type);
      if (total_length + length + 3 > size) {
         return -1;
      }
      buffer[total_length] = length;

      memcpy(buffer + total_length + 1, content_type, length);
      total_length += length + 1;
      *(uint16_t *) (buffer + total_length) = ntohs(code);
      total_length += 2;

      return total_length;
   }
};

/**
 * \brief Flow cache plugin used to parse HTTP requests / responses.
 */
class HTTPPlugin : public FlowCachePlugin
{
public:
   HTTPPlugin(const options_t &module_options);
   HTTPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   ~HTTPPlugin();
   FlowCachePlugin *copy();
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish();
   string get_unirec_field_string();
   const char **get_ipfix_string();

private:
   bool is_response(const char *data, int payload_len);
   bool is_request(const char *data, int payload_len);
   bool parse_http_request(const char *data, int payload_len, RecordExtHTTP *rec);
   bool parse_http_response(const char *data, int payload_len, RecordExtHTTP *rec);
   void add_ext_http_request(const char *data, int payload_len, Flow &flow);
   void add_ext_http_response(const char *data, int payload_len, Flow &flow);
   bool valid_http_method(const char *method) const;

   RecordExtHTTP *recPrealloc;/**< Preallocated extension. */
   bool print_stats;          /**< Print stats when flow cache is finishing. */
   bool flush_flow;           /**< Tell FlowCache to flush current Flow. */
   uint32_t requests;         /**< Total number of parsed HTTP requests. */
   uint32_t responses;        /**< Total number of parsed HTTP responses. */
   uint32_t total;            /**< Total number of parsed HTTP packets. */
};

#endif
