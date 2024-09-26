/**
 * \file rtsp.hpp
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
 *
 *
 */

#ifndef IPXP_PROCESS_RTSP_HPP
#define IPXP_PROCESS_RTSP_HPP

#include <cstring>
#include <cstdlib>
#include <iostream>
#include <sstream>

#ifdef WITH_NEMEA
#include <fields.h>
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include "http.hpp"

namespace ipxp {

#define RTSP_UNIREC_TEMPLATE "RTSP_REQUEST_METHOD,RTSP_REQUEST_AGENT,RTSP_REQUEST_URI,RTSP_RESPONSE_STATUS_CODE,RTSP_RESPONSE_SERVER,RTSP_RESPONSE_CONTENT_TYPE"
UR_FIELDS (
   string RTSP_REQUEST_METHOD,
   string RTSP_REQUEST_AGENT,
   string RTSP_REQUEST_URI,

   uint16 RTSP_RESPONSE_STATUS_CODE,
   string RTSP_RESPONSE_SERVER,
   string RTSP_RESPONSE_CONTENT_TYPE
)

/**
 * \brief Flow record extension header for storing RTSP requests.
 */
struct RecordExtRTSP : public RecordExt {
   static int REGISTERED_ID;
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
   RecordExtRTSP() : RecordExt(REGISTERED_ID)
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

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_RTSP_REQUEST_METHOD, method);
      ur_set_string(tmplt, record, F_RTSP_REQUEST_AGENT, user_agent);
      ur_set_string(tmplt, record, F_RTSP_REQUEST_URI, uri);

      ur_set(tmplt, record, F_RTSP_RESPONSE_STATUS_CODE, code);
      ur_set_string(tmplt, record, F_RTSP_RESPONSE_SERVER, server);
      ur_set_string(tmplt, record, F_RTSP_RESPONSE_CONTENT_TYPE, content_type);
   }

   const char *get_unirec_tmplt() const
   {
      return RTSP_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
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
      total_length += length + 1;

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

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_RTSP_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };
      return ipfix_template;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "httpmethod=\"" << method << "\""
         << ",uri=\"" << uri << "\""
         << ",agent=\"" << user_agent << "\""
         << ",server=\"" << server << "\""
         << ",content=\"" << content_type << "\""
         << ",status=" << code;
      return out.str();
   }
};

/**
 * \brief Flow cache plugin used to parse RTSP requests / responses.
 */
class RTSPPlugin : public ProcessPlugin
{
public:
   RTSPPlugin();
   ~RTSPPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("rtsp", "Parse RTSP traffic"); }
   std::string get_name() const { return "rtsp"; }
   RecordExt *get_ext() const { return new RecordExtRTSP(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish(bool print_stats);

private:
   bool is_response(const char *data, int payload_len);
   bool is_request(const char *data, int payload_len);
   bool parse_rtsp_request(const char *data, int payload_len, RecordExtRTSP *rec);
   bool parse_rtsp_response(const char *data, int payload_len, RecordExtRTSP *rec);
   void add_ext_rtsp_request(const char *data, int payload_len, Flow &flow);
   void add_ext_rtsp_response(const char *data, int payload_len, Flow &flow);
   bool valid_rtsp_method(const char *method) const;

   RecordExtRTSP *recPrealloc;/**< Preallocated extension. */
   bool flow_flush;           /**< Tell storage plugin to flush current Flow. */
   uint32_t requests;         /**< Total number of parsed RTSP requests. */
   uint32_t responses;        /**< Total number of parsed RTSP responses. */
   uint32_t total;            /**< Total number of parsed RTSP packets. */
};

}
#endif /* IPXP_PROCESS_RTSP_HPP */
