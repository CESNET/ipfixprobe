/*
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
*/

#ifndef _HTTP_PLUGIN_P4_
#define _HTTP_PLUGIN_P4_

#include <core.p4>
#include "types.p4"
#include "ipfix.p4"
#include "plugin.p4"

header http_request_h
{
   @string("10") bit<80> method; // 10 bytes
   @string("128") bit<1024> uri; // 128 bytes
   @string("64") bit<512> host; // 64 bytes
   @string("128") bit<1024> referer; // 128 bytes
   @string("128") bit<1024> agent; // 128 bytes
}
header http_response_h
{
   bit<16> code;
   @string("64") bit<512> content_type; // 64 bytes
}
header_union http_u
{
   http_request_h req;
   http_response_h resp;
}
struct http_extension_s
{
   bit<8> type;
   http_u data;
}

#define HTTP_REQUEST 1
#define HTTP_RESPONSE 2

parser http_plugin_parser(payload p, out http_extension_s ext)
{
   @regex("(\"GET\"|\"POST\"|\"PUT\"|\"HEAD\"|\"DELETE\"|\"TRACE\"|\"OPTIONS\"|\"CONNECT\"|\"PATCH\")[ ]([^ ]*)[ ]\"HTTP\"[/][0-9][.][0-9]\"\r\n\"")
   bit<1> header_req;

   @regex("\"HTTP\"[/][0-9][.][0-9][ ]([0-9]*)[ ].*\"\r\n\"")
   bit<1> header_resp;

   @regex("([^:]*)\": \"(.*)\"\r\n\"")
   bit<1> http_keyval;

   @regex("\"\r\n\"")
   bit<1> end_of_header_fields;

   @string("512") bit<1> key;
   @string("512") bit<1> val;

   @string("10") bit<1> method;
   @string("128") bit<1> uri;
   @string("10") bit<1> resp_code;

   state start {
      transition parse_header_request;
   }
   state parse_header_request {
      transition select(p.extract_re(header_req, {method, uri})) {
         true: parse_header_request_check;
         false: parse_header_response;
      }
   }
   state parse_header_response {
      transition select(p.extract_re(header_resp, resp_code)) {
         true: parse_header_response_check;
         false: reject;
      }
   }
   state parse_header_request_check {
      transition select(ext.type) {
         0: parse_header_request_;
         default: flush;
      }
   }
   state parse_header_request_ {
      p.strcpy(ext.data.req.method, method);
      p.strcpy(ext.data.req.uri, uri);

      ext.type = HTTP_REQUEST;
      transition parse_fields_request;
   }
   state parse_header_response_check {
      transition select(ext.type) {
         0: parse_header_response_;
         default: flush;
      }
   }
   state parse_header_response_ {
      p.to_number(resp_code, ext.data.resp.code);

      ext.type = HTTP_RESPONSE;
      transition parse_fields_response;
   }
   state parse_fields_request {
      // Parse HTTP header fields

      transition select(p.extract_re(http_keyval, {key, val})) {
         true: check_host;
         false: accept;
      }
   }
   state check_host {
      @regex("\"Host\x00\"")
      bit<1> host_str;

      transition select(p.match(host_str, key)) {
         true: parse_host;
         default: check_agent;
      }
   }
   state check_agent {
      @regex("\"User-Agent\x00\"")
      bit<1> agent_str;

      transition select(p.match(agent_str, key)) {
         true: parse_agent;
         default: check_referer;
      }
   }
   state check_referer {
      @regex("\"Referer\x00\"")
      bit<1> referer_str;

      transition select(p.match(referer_str, key)) {
         true: parse_referer;
         default: parse_fields_request;
      }
   }
   state parse_host {
      p.strcpy(ext.data.req.host, val);
      transition parse_fields_request;
   }
   state parse_agent {
      p.strcpy(ext.data.req.agent, val);
      transition parse_fields_request;
   }
   state parse_referer {
      p.strcpy(ext.data.req.referer, val);
      transition parse_fields_request;
   }

   state parse_fields_response {
      transition select(p.extract_re(http_keyval, {key, val})) {
         true: extract_fields_response;
         false: accept;
      }
   }
   state extract_fields_response {
      @regex("\"Content-Type\x00\"")
      bit<1> content_str;

      transition select(p.match(content_str, key)) {
         true: parse_content;
         default: parse_fields_response;
      }
   }
   state parse_content {
      p.strcpy(ext.data.resp.content_type, val);
      transition parse_fields_response;
   }
   state flush {
      transition reject;
   }
}

control http_plugin_export(in flowrec_s flow, in http_extension_s ext, ipfix_exporter e)
{
   apply {
      FILL_IPFIX_TEMPLATE(IPFIX_TEMPLATE_IPV4_HTTP, IPFIX_TEMPLATE_IPV6_HTTP);

      if (ext.type == HTTP_REQUEST) {
         e.add_field(ext.data.req.agent);
         e.add_field(ext.data.req.method);
         e.add_field(ext.data.req.host);
         e.add_field(ext.data.req.referer);
         e.add_field(ext.data.req.uri);
         e.add_field_empty();
         e.add_field((bit<16>) 0);
         e.set_finish();
      } else {
         e.add_field_empty();
         e.add_field_empty();
         e.add_field_empty();
         e.add_field_empty();
         e.add_field_empty();
         e.add_field(ext.data.resp.content_type);
         e.add_field(ext.data.resp.code);
         e.set_finish();
      }
   }
}

#endif