/**
 * \file http.hpp
 * \brief Plugin for parsing HTTP traffic
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

#ifndef IPXP_PROCESS_HTTP_HPP
#define IPXP_PROCESS_HTTP_HPP

#include <config.h>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <iostream>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

#define HTTP_UNIREC_TEMPLATE  "HTTP_REQUEST_METHOD,HTTP_REQUEST_HOST,HTTP_REQUEST_URL,HTTP_REQUEST_AGENT,HTTP_REQUEST_REFERER,HTTP_RESPONSE_STATUS_CODE,HTTP_RESPONSE_CONTENT_TYPE,HTTP_RESPONSE_SERVER,HTTP_RESPONSE_SET_COOKIE_NAMES"

UR_FIELDS (
   string HTTP_REQUEST_METHOD,
   string HTTP_REQUEST_HOST,
   string HTTP_REQUEST_URL,
   string HTTP_REQUEST_AGENT,
   string HTTP_REQUEST_REFERER,

   uint16 HTTP_RESPONSE_STATUS_CODE,
   string HTTP_RESPONSE_CONTENT_TYPE,
   string HTTP_RESPONSE_SERVER,
   string HTTP_RESPONSE_SET_COOKIE_NAMES
)

void copy_str(char *dst, ssize_t size, const char *begin, const char *end);
void add_str(char *dst, ssize_t size, const char *begin, const char *end, const char* delimiter);

/**
 * \brief Flow record extension header for storing HTTP requests.
 */
struct RecordExtHTTP : public RecordExt {
   static int REGISTERED_ID;

   bool req;
   bool resp;

   char method[16];
   char host[64];
   char uri[128];
   char user_agent[128];
   char referer[128];

   uint16_t code;
   char content_type[32];

   char server[128];
   char set_cookie[512];

   /**
    * \brief Constructor.
    */
   RecordExtHTTP() : RecordExt(REGISTERED_ID)
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
      server[0] = 0;
      set_cookie[0] = 0;
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_HTTP_REQUEST_METHOD, method);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_HOST, host);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_URL, uri);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_AGENT, user_agent);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_REFERER, referer);
      ur_set_string(tmplt, record, F_HTTP_RESPONSE_CONTENT_TYPE, content_type);
      ur_set(tmplt, record, F_HTTP_RESPONSE_STATUS_CODE, code);
      ur_set_string(tmplt, record, F_HTTP_RESPONSE_SERVER, server);
      ur_set_string(tmplt, record, F_HTTP_RESPONSE_SET_COOKIE_NAMES, set_cookie);
   }

   const char *get_unirec_tmplt() const
   {
      return HTTP_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      uint16_t length = 0;
      uint32_t total_length = 0;

      length = strlen(user_agent);
      if ((uint32_t) (length + 3) > (uint32_t) size) {
         return -1;
      }
      total_length += variable2ipfix_buffer(buffer + total_length, (uint8_t*) user_agent, length);

      length = strlen(method);
      if (total_length + length + 3 > (uint32_t) size) {
         return -1;
      }
      total_length += variable2ipfix_buffer(buffer + total_length, (uint8_t*) method, length);

      length = strlen(host);
      if (total_length + length + 3 > (uint32_t) size) {
         return -1;
      }
      total_length += variable2ipfix_buffer(buffer + total_length, (uint8_t*) host, length);

      length = strlen(referer);
      if (total_length + length + 3 > (uint32_t) size) {
         return -1;
      }
      total_length += variable2ipfix_buffer(buffer + total_length, (uint8_t*) referer, length);

      length = strlen(uri);
      if (total_length + length + 3 > (uint32_t) size) {
         return -1;
      }
      total_length += variable2ipfix_buffer(buffer + total_length, (uint8_t*) uri, length);

      length = strlen(content_type);
      if (total_length + length + 3 > (uint32_t) size) {
         return -1;
      }
      total_length += variable2ipfix_buffer(buffer + total_length, (uint8_t*) content_type, length);

      length = strlen(server);
      if (total_length + length + 3 > (uint32_t) size) {
         return -1;
      }
      total_length += variable2ipfix_buffer(buffer + total_length, (uint8_t*) server, length);

      length = strlen(set_cookie);
      if (total_length + length + 3 > (uint32_t) size) {
         return -1;
      }
      total_length += variable2ipfix_buffer(buffer + total_length, (uint8_t*) set_cookie, length);

      *(uint16_t *) (buffer + total_length) = ntohs(code);
      total_length += 2;

      return total_length;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_HTTP_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };
      return ipfix_template;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "method=\"" << method << "\""
         << ",host=\"" << host << "\""
         << ",uri=\"" << uri << "\""
         << ",agent=\"" << user_agent << "\""
         << ",referer=\"" << referer << "\""
         << ",content=\"" << content_type << "\""
         << ",status=" << code
         << ",server=\"" << server << "\""
         << ",set-cookie=\"" << set_cookie << "\"";
      return out.str();
   }
};

/**
 * \brief Flow cache plugin used to parse HTTP requests / responses.
 */
class HTTPPlugin : public ProcessPlugin
{
public:
   HTTPPlugin();
   ~HTTPPlugin();
   void init(const char *params);
   void close();
   RecordExt *get_ext() const { return new RecordExtHTTP(); }
   OptionsParser *get_parser() const { return new OptionsParser("http", "Parse HTTP traffic"); }
   std::string get_name() const { return "http"; }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish(bool print_stats);

private:
   bool is_response(const char *data, int payload_len);
   bool is_request(const char *data, int payload_len);
   bool parse_http_request(const char *data, int payload_len, RecordExtHTTP *rec);
   bool parse_http_response(const char *data, int payload_len, RecordExtHTTP *rec);
   void add_ext_http_request(const char *data, int payload_len, Flow &flow);
   void add_ext_http_response(const char *data, int payload_len, Flow &flow);
   bool valid_http_method(const char *method) const;
   bool invalid_http_method(const char *payload, int payload_len) const;

   RecordExtHTTP *recPrealloc;/**< Preallocated extension. */
   bool flow_flush;           /**< Tell storage plugin to flush current Flow. */
   uint32_t requests;         /**< Total number of parsed HTTP requests. */
   uint32_t responses;        /**< Total number of parsed HTTP responses. */
   uint32_t total;            /**< Total number of parsed HTTP packets. */
};

}
#endif /* IPXP_PROCESS_HTTP_HPP */
