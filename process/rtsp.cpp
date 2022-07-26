/**
 * \file rtsp.cpp
 * \brief Plugin for parsing RTSP traffic
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
#include <cstring>
#include <cstdlib>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "common.hpp"
#include "rtsp.hpp"

namespace ipxp {

int RecordExtRTSP::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("rtsp", [](){return new RTSPPlugin();});
   register_plugin(&rec);
   RecordExtRTSP::REGISTERED_ID = register_extension();
}

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

#define RTSP_LINE_DELIMITER   '\n'
#define RTSP_KEYVAL_DELIMITER ':'

RTSPPlugin::RTSPPlugin() : recPrealloc(nullptr), flow_flush(false),
   requests(0), responses(0), total(0)
{
}

RTSPPlugin::~RTSPPlugin()
{
   close();
}

void RTSPPlugin::init(const char *params)
{
}

void RTSPPlugin::close()
{
   if (recPrealloc != nullptr) {
      delete recPrealloc;
      recPrealloc = nullptr;
   }
}

ProcessPlugin *RTSPPlugin::copy()
{
   return new RTSPPlugin(*this);
}

int RTSPPlugin::post_create(Flow &rec, const Packet &pkt)
{
   const char *payload = reinterpret_cast<const char *>(pkt.payload);
   if (is_request(payload, pkt.payload_len)) {
      add_ext_rtsp_request(payload, pkt.payload_len, rec);
   } else if (is_response(payload, pkt.payload_len)) {
      add_ext_rtsp_response(payload, pkt.payload_len, rec);
   }

   return 0;
}

int RTSPPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExt *ext = nullptr;
   const char *payload = reinterpret_cast<const char *>(pkt.payload);
   if (is_request(payload, pkt.payload_len)) {
      ext = rec.get_extension(RecordExtRTSP::REGISTERED_ID);
      if (ext == nullptr) { /* Check if header is present in flow. */
         add_ext_rtsp_request(payload, pkt.payload_len, rec);
         return 0;
      }

      parse_rtsp_request(payload, pkt.payload_len, static_cast<RecordExtRTSP *>(ext));
      if (flow_flush) {
         flow_flush = false;
         return FLOW_FLUSH_WITH_REINSERT;
      }
   } else if (is_response(payload, pkt.payload_len)) {
      ext = rec.get_extension(RecordExtRTSP::REGISTERED_ID);
      if (ext == nullptr) { /* Check if header is present in flow. */
         add_ext_rtsp_response(payload, pkt.payload_len, rec);
         return 0;
      }

      parse_rtsp_response(payload, pkt.payload_len, static_cast<RecordExtRTSP *>(ext));
      if (flow_flush) {
         flow_flush = false;
         return FLOW_FLUSH_WITH_REINSERT;
      }
   }

   return 0;
}

void RTSPPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "RTSP plugin stats:" << std::endl;
      std::cout << "   Parsed rtsp requests: " << requests << std::endl;
      std::cout << "   Parsed rtsp responses: " << responses << std::endl;
      std::cout << "   Total rtsp packets processed: " << total << std::endl;
   }
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
   const char *begin;
   const char *end;
   const char *keyval_delimiter;
   size_t remaining;

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
   begin = static_cast<const char *>(memchr(data, ' ', payload_len));
   if (begin == nullptr) {
      DEBUG_MSG("Parser quits:\tnot a rtsp request header\n");
      return false;
   }

   /* Find end of URI. */
   
   if (check_payload_len(payload_len, (begin + 1) - data)) {
      DEBUG_MSG("Parser quits:\tpayload end\n");
      return false;
   }
   remaining = payload_len - ((begin + 1) - data);
   end = static_cast<const char *>(memchr(begin + 1, ' ', remaining));
   if (end == nullptr) {
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
      flow_flush = true;
      total--;
      DEBUG_MSG("Parser quits:\tflushing flow\n");
      return false;
   }
   strncpy(rec->method, buffer, sizeof(rec->method));
   rec->method[sizeof(rec->method) - 1] = 0;

   copy_str(rec->uri, sizeof(rec->uri), begin + 1, end);
   DEBUG_MSG("\tMethod: %s\n",   rec->method);
   DEBUG_MSG("\tURI: %s\n",      rec->uri);

   /* Find begin of next line after request line. */
   if (check_payload_len(payload_len, end - data)) {
      DEBUG_MSG("Parser quits:\tpayload end\n");
      return false;
   }
   remaining = payload_len - (end - data);
   begin = static_cast<const char *>(memchr(end, RTSP_LINE_DELIMITER, remaining));
   if (begin == nullptr) {
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
      remaining = payload_len - (begin - data);
      end = static_cast<const char *>(memchr(begin, RTSP_LINE_DELIMITER, remaining));
      keyval_delimiter = static_cast<const char *>(memchr(begin, RTSP_KEYVAL_DELIMITER, remaining));

      int tmp = end - begin;
      if (tmp == 0 || tmp == 1) { /* Check for blank line with \r\n or \n ending. */
         break; /* Double LF found - end of header section. */
      } else if (end == nullptr || keyval_delimiter == NULL) {
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
   const char *begin;
   const char *end;
   const char *keyval_delimiter;
   size_t remaining;
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
   begin = static_cast<const char *>(memchr(data, ' ', payload_len));
   if (begin == nullptr) {
      DEBUG_MSG("Parser quits:\tnot a rtsp response header\n");
      return false;
   }

   /* Find end of status code. */
   if (check_payload_len(payload_len, (begin + 1) - data)) {
      DEBUG_MSG("Parser quits:\tpayload end\n");
      return false;
   }
   remaining = payload_len - ((begin + 1) - data);
   end = static_cast<const char *>(memchr(begin + 1, ' ', remaining));
   if (end == nullptr) {
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
      flow_flush = true;
      total--;
      DEBUG_MSG("Parser quits:\tflushing flow\n");
      return false;
   }
   rec->code = code;

   /* Find begin of next line after request line. */
   if (check_payload_len(payload_len, end - data)) {
      DEBUG_MSG("Parser quits:\tpayload end\n");
      return false;
   }
   remaining = payload_len - (end - data);
   begin = static_cast<const char *>(memchr(end, RTSP_LINE_DELIMITER, remaining));
   if (begin == nullptr) {
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
      remaining = payload_len - (begin - data);
      end = static_cast<const char *>(memchr(begin, RTSP_LINE_DELIMITER, remaining));
      keyval_delimiter = static_cast<const char *>(memchr(begin, RTSP_KEYVAL_DELIMITER, remaining));

      int tmp = end - begin;
      if (tmp == 0 || tmp == 1) { /* Check for blank line with \r\n or \n ending. */
         break; /* Double LF found - end of header section. */
      } else if (end == nullptr || keyval_delimiter == NULL) {
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
   if (recPrealloc == nullptr) {
      recPrealloc = new RecordExtRTSP();
   }

   if (parse_rtsp_request(data, payload_len, recPrealloc)) {
      flow.add_extension(recPrealloc);
      recPrealloc = nullptr;
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
   if (recPrealloc == nullptr) {
      recPrealloc = new RecordExtRTSP();
   }

   if (parse_rtsp_response(data, payload_len, recPrealloc)) {
      flow.add_extension(recPrealloc);
      recPrealloc = nullptr;
   }
}

}
