/**
 * \file rtspplugin.cpp
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

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unirec/unirec.h>

#include "packet.h"
#include "flowifc.h"
#include "rtspplugin.h"
#include "ipfix-elements.h"

using namespace std;

//#define DEBUG_RTSP

// Print debug message if debugging is allowed.
#ifdef DEBUG_RTSP
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_RTSP
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

#define RTSP_UNIREC_TEMPLATE "RTSP_REQUEST_METHOD,RTSP_REQUEST_AGENT,RTSP_REQUEST_URI,RTSP_RESPONSE_STATUS_CODE,RTSP_RESPONSE_SERVER,RTSP_RESPONSE_CONTENT_TYPE"
#define RTSP_LINE_DELIMITER   '\n'
#define RTSP_KEYVAL_DELIMITER ':'

UR_FIELDS (
   string RTSP_REQUEST_METHOD,
   string RTSP_REQUEST_AGENT,
   string RTSP_REQUEST_URI,

   uint16 RTSP_RESPONSE_STATUS_CODE,
   string RTSP_RESPONSE_SERVER,
   string RTSP_RESPONSE_CONTENT_TYPE
)

/**
 * \brief Constructor.
 * \param [in] options Module options.
 */
RTSPPlugin::RTSPPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
   requests = 0;
   responses = 0;
   total = 0;
   flush_flow = false;
   recPrealloc = NULL;
}

RTSPPlugin::RTSPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   requests = 0;
   responses = 0;
   total = 0;
   flush_flow = false;
   recPrealloc = NULL;
}

RTSPPlugin::~RTSPPlugin()
{
   if (recPrealloc == NULL) {
      delete recPrealloc;
   }
}

int RTSPPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (is_request(pkt.payload, pkt.payload_length)) {
      add_ext_rtsp_request(pkt.payload, pkt.payload_length, rec);
   } else if (is_response(pkt.payload, pkt.payload_length)) {
      add_ext_rtsp_response(pkt.payload, pkt.payload_length, rec);
   }

   return 0;
}

int RTSPPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExt *ext = NULL;
   if (is_request(pkt.payload, pkt.payload_length)) {
      ext = rec.getExtension(rtsp);
      if (ext == NULL) { /* Check if header is present in flow. */
         add_ext_rtsp_request(pkt.payload, pkt.payload_length, rec);
         return 0;
      }

      parse_rtsp_request(pkt.payload, pkt.payload_length, dynamic_cast<RecordExtRTSP *>(ext));
      if (flush_flow) {
         flush_flow = false;
         return FLOW_FLUSH_WITH_REINSERT;
      }
   } else if (is_response(pkt.payload, pkt.payload_length)) {
      ext = rec.getExtension(rtsp);
      if (ext == NULL) { /* Check if header is present in flow. */
         add_ext_rtsp_response(pkt.payload, pkt.payload_length, rec);
         return 0;
      }

      parse_rtsp_response(pkt.payload, pkt.payload_length, dynamic_cast<RecordExtRTSP *>(ext));
      if (flush_flow) {
         flush_flow = false;
         return FLOW_FLUSH_WITH_REINSERT;
      }
   }

   return 0;
}

void RTSPPlugin::finish()
{
   if (print_stats) {
      cout << "RTSP plugin stats:" << endl;
      cout << "   Parsed rtsp requests: " << requests << endl;
      cout << "   Parsed rtsp responses: " << responses << endl;
      cout << "   Total rtsp packets processed: " << total << endl;
   }
}

string RTSPPlugin::get_unirec_field_string()
{
   return RTSP_UNIREC_TEMPLATE;
}

const char *ipfix_rtsp_template[] = {
   IPFIX_RTSP_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **RTSPPlugin::get_ipfix_string()
{
   return ipfix_rtsp_template;
}

bool RTSPPlugin::is_request(const char *data, int payload_len)
{
   char chars[5];

   if (payload_len < 4) {
      return false;
   }
   memcpy(chars, data, 4);
   chars[4] = 0;
   return valid_rtsp_method(chars);
}

bool RTSPPlugin::is_response(const char *data, int payload_len)
{
   char chars[5];

   if (payload_len < 4) {
      return false;
   }
   memcpy(chars, data, 4);
   chars[4] = 0;
   return !strcmp(chars, "RTSP");
}

#ifdef DEBUG_RTSP
static uint32_t s_requests = 0, s_responses = 0;
#endif /* DEBUG_RTSP */

/**
 * \brief Parse and store rtsp request.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] rec Variable where rtsp request will be stored.
 * \return True if request was parsed, false if error occured.
 */
bool RTSPPlugin::parse_rtsp_request(const char *data, int payload_len, RecordExtRTSP *rec)
{
   char buffer[64];
   const char *begin, *end, *keyval_delimiter;

   total++;

   DEBUG_MSG("---------- rtsp parser #%u ----------\n", total);
   DEBUG_MSG("Parsing request number: %u\n", ++s_requests);
   DEBUG_MSG("Payload length: %u\n\n",       payload_len);

   if (payload_len == 0) {
      DEBUG_MSG("Parser quits:\tpayload length = 0\n");
      return false;
   }

   /* Request line:
    *
    * METHOD URI VERSION
    * |     |   |
    * |     |   -------- end
    * |     ------------ begin
    * ----- ------------ data
    */

   /* Find begin of URI. */
   begin = strchr(data, ' ');
   if (begin == NULL) {
      DEBUG_MSG("Parser quits:\tnot a rtsp request header\n");
      return false;
   }

   /* Find end of URI. */
   end = strchr(begin + 1, ' ');
   if (end == NULL) {
      DEBUG_MSG("Parser quits:\trequest is fragmented\n");
      return false;
   }

   if (memcmp(end + 1, "RTSP", 4)) {
      DEBUG_MSG("Parser quits:\tnot a RTSP request\n");
      return false;
   }

   /* Copy and check RTSP method */
   copy_str(buffer, sizeof(buffer), data, begin);
   if (rec->req) {
      flush_flow = true;
      total--;
      DEBUG_MSG("Parser quits:\tflushing flow\n");
      return false;
   }
   strcpy(rec->method, buffer);

   copy_str(rec->uri, sizeof(rec->uri), begin + 1, end);
   DEBUG_MSG("\tMethod: %s\n",   rec->method);
   DEBUG_MSG("\tURI: %s\n",      rec->uri);

   /* Find begin of next line after request line. */
   begin = strchr(end, RTSP_LINE_DELIMITER);
   if (begin == NULL) {
      DEBUG_MSG("Parser quits:\tNo line delim after request line\n");
      return false;
   }
   begin++;

   /* Header:
    *
    * REQ-FIELD: VALUE
    * |        |      |
    * |        |      ----- end
    * |        ------------ keyval_delimiter
    * --------------------- begin
    */

   rec->user_agent[0] = 0;
   /* Process headers. */
   while (begin - data < payload_len) {
      end = strchr(begin, RTSP_LINE_DELIMITER);
      keyval_delimiter = strchr(begin, RTSP_KEYVAL_DELIMITER);

      int tmp = end - begin;
      if (tmp == 0 || tmp == 1) { /* Check for blank line with \r\n or \n ending. */
         break; /* Double LF found - end of header section. */
      } else if (end == NULL || keyval_delimiter == NULL) {
         DEBUG_MSG("Parser quits:\theader is fragmented\n");
         return  false;
      }

      /* Copy field name. */
      copy_str(buffer, sizeof(buffer), begin, keyval_delimiter);

      DEBUG_CODE(char debug_buffer[4096]);
      DEBUG_CODE(copy_str(debug_buffer, sizeof(debug_buffer), keyval_delimiter + 2, end));
      DEBUG_MSG("\t%s: %s\n", buffer, debug_buffer);

      /* Copy interesting field values. */
      if (!strcmp(buffer, "User-Agent")) {
         copy_str(rec->user_agent, sizeof(rec->user_agent), keyval_delimiter + 2, end);
      }

      /* Go to next line. */
      begin = end + 1 ;
   }

   DEBUG_MSG("Parser quits:\tend of header section\n");
   rec->req = true;
   requests++;
   return true;
}

/**
 * \brief Parse and store rtsp response.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] rec Variable where rtsp response will be stored.
 * \return True if request was parsed, false if error occured.
 */
bool RTSPPlugin::parse_rtsp_response(const char *data, int payload_len, RecordExtRTSP *rec)
{
   char buffer[64];
   const char *begin, *end, *keyval_delimiter;
   int code;

   total++;

   DEBUG_MSG("---------- rtsp parser #%u ----------\n", total);
   DEBUG_MSG("Parsing response number: %u\n",   ++s_responses);
   DEBUG_MSG("Payload length: %u\n\n",          payload_len);

   if (payload_len == 0) {
      DEBUG_MSG("Parser quits:\tpayload length = 0\n");
      return false;
   }

   /* Check begin of response header. */
   if (memcmp(data, "RTSP", 4)) {
      DEBUG_MSG("Parser quits:\tpacket contains rtsp response data\n");
      return false;
   }

   /* Response line:
    *
    * VERSION CODE REASON
    * |      |    |
    * |      |    --------- end
    * |      -------------- begin
    * --------------------- data
    */

   /* Find begin of status code. */
   begin = strchr(data, ' ');
   if (begin == NULL) {
      DEBUG_MSG("Parser quits:\tnot a rtsp response header\n");
      return false;
   }

   /* Find end of status code. */
   end = strchr(begin + 1, ' ');
   if (end == NULL) {
      DEBUG_MSG("Parser quits:\tresponse is fragmented\n");
      return false;
   }

   /* Copy and check RTSP response code. */
   copy_str(buffer, sizeof(buffer), begin + 1, end);
   code = atoi(buffer);
   if (code <= 0) {
      DEBUG_MSG("Parser quits:\twrong response code: %d\n", code);
      return false;
   }

   DEBUG_MSG("\tCode: %d\n", code);
   if (rec->resp) {
      flush_flow = true;
      total--;
      DEBUG_MSG("Parser quits:\tflushing flow\n");
      return false;
   }
   rec->code = code;

   /* Find begin of next line after request line. */
   begin = strchr(end, RTSP_LINE_DELIMITER);
   if (begin == NULL) {
      DEBUG_MSG("Parser quits:\tNo line delim after request line\n");
      return false;
   }
   begin++;

   /* Header:
    *
    * REQ-FIELD: VALUE
    * |        |      |
    * |        |      ----- end
    * |        ------------ keyval_delimiter
    * --------------------- begin
    */

   rec->content_type[0] = 0;
   /* Process headers. */
   while (begin - data < payload_len) {
      end = strchr(begin, RTSP_LINE_DELIMITER);
      keyval_delimiter = strchr(begin, RTSP_KEYVAL_DELIMITER);

      int tmp = end - begin;
      if (tmp == 0 || tmp == 1) { /* Check for blank line with \r\n or \n ending. */
         break; /* Double LF found - end of header section. */
      } else if (end == NULL || keyval_delimiter == NULL) {
         DEBUG_MSG("Parser quits:\theader is fragmented\n");
         return  false;
      }

      /* Copy field name. */
      copy_str(buffer, sizeof(buffer), begin, keyval_delimiter);

      DEBUG_CODE(char debug_buffer[4096]);
      DEBUG_CODE(copy_str(debug_buffer, sizeof(debug_buffer), keyval_delimiter + 2, end));
      DEBUG_MSG("\t%s: %s\n", buffer, debug_buffer);

      /* Copy interesting field values. */
      if (!strcmp(buffer, "Content-Type")) {
         copy_str(rec->content_type, sizeof(rec->content_type), keyval_delimiter + 2, end);
      } else if (!strcmp(buffer, "Server")) {
         copy_str(rec->server, sizeof(rec->server), keyval_delimiter + 2, end);
      }

      /* Go to next line. */
      begin = end + 1 ;
   }

   DEBUG_MSG("Parser quits:\tend of header section\n");
   rec->resp = true;
   responses++;
   return true;
}

/**
 * \brief Check rtsp method.
 * \param [in] method C string with rtsp method.
 * \return True if rtsp method is valid.
 */
bool RTSPPlugin::valid_rtsp_method(const char *method) const
{
   return (!strcmp(method, "GET ") || !strcmp(method, "POST") ||
           !strcmp(method, "PUT ") || !strcmp(method, "HEAD") ||
           !strcmp(method, "DELE") || !strcmp(method, "TRAC") ||
           !strcmp(method, "OPTI") || !strcmp(method, "CONN") ||
           !strcmp(method, "PATC") ||
           !strcmp(method, "DESC") || !strcmp(method, "SETU") ||
           !strcmp(method, "PLAY") || !strcmp(method, "PAUS") ||
           !strcmp(method, "TEAR") || !strcmp(method, "RECO") ||
           !strcmp(method, "ANNO"));
}

/**
 * \brief Add new extension rtsp request header into flow record.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] flow Flow record where to store created extension header.
 */
void RTSPPlugin::add_ext_rtsp_request(const char *data, int payload_len, Flow &flow)
{
   if (recPrealloc == NULL) {
      recPrealloc = new RecordExtRTSP();
   }

   if (parse_rtsp_request(data, payload_len, recPrealloc)) {
      flow.addExtension(recPrealloc);
      recPrealloc = NULL;
   }
}

/**
 * \brief Add new extension rtsp response header into flow record.
 * \param [in] data Packet payload data.
 * \param [in] payload_len Length of packet payload.
 * \param [out] flow Flow record where to store created extension header.
 */
void RTSPPlugin::add_ext_rtsp_response(const char *data, int payload_len, Flow &flow)
{
   if (recPrealloc == NULL) {
      recPrealloc = new RecordExtRTSP();
   }

   if (parse_rtsp_response(data, payload_len, recPrealloc)) {
      flow.addExtension(recPrealloc);
      recPrealloc = NULL;
   }
}

