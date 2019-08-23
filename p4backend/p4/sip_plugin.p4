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

#ifndef _SIP_PLUGIN_P4_
#define _SIP_PLUGIN_P4_

#include <core.p4>
#include "types.p4"
#include "ipfix.p4"
#include "plugin.p4"

#define SIP_MSG_TYPE_INVALID     0
#define SIP_MSG_TYPE_INVITE      1
#define SIP_MSG_TYPE_ACK         2
#define SIP_MSG_TYPE_CANCEL      3
#define SIP_MSG_TYPE_BYE         4
#define SIP_MSG_TYPE_REGISTER    5
#define SIP_MSG_TYPE_OPTIONS     6
#define SIP_MSG_TYPE_PUBLISH     7
#define SIP_MSG_TYPE_NOTIFY      8
#define SIP_MSG_TYPE_INFO        9
#define SIP_MSG_TYPE_SUBSCRIBE   10
#define SIP_MSG_TYPE_STATUS      99

#define SIP_MSG_TYPE_TRYING         100
#define SIP_MSG_TYPE_DIAL_ESTABL    101
#define SIP_MSG_TYPE_RINGING        180
#define SIP_MSG_TYPE_SESSION_PROGR  183
#define SIP_MSG_TYPE_OK             200
#define SIP_MSG_TYPE_BAD_REQ        400
#define SIP_MSG_TYPE_UNAUTHORIZED   401
#define SIP_MSG_TYPE_FORBIDDEN      403
#define SIP_MSG_TYPE_NOT_FOUND      404
#define SIP_MSG_TYPE_PROXY_AUT_REQ  407
#define SIP_MSG_TYPE_BUSY_HERE      486
#define SIP_MSG_TYPE_REQ_CANCELED   487
#define SIP_MSG_TYPE_INTERNAL_ERR   500
#define SIP_MSG_TYPE_DECLINE        603
#define SIP_MSG_TYPE_UNDEFINED      999

struct sip_extension_s
{
   bit<16> msg_type;
   bit<16> status_code;
   @stringbuf("128") bit<1> call_id;
   @stringbuf("128") bit<1> calling_party;
   @stringbuf("128") bit<1> called_party;
   @stringbuf("128") bit<1> via;
   @stringbuf("128") bit<1> user_agent;
   @stringbuf("128") bit<1> cseq;
   @stringbuf("128") bit<1> request_uri;
}

parser sip_plugin_parser(payload p, out sip_extension_s ext)
{
   @regex("(\"REGISTER\"|\"INVITE\"|\"ACK\"|\"BYE\"|\"CANCEL\"|\"UPDATE\"|\"REFER\"|\"PRACK\"|\"SUBSCRIBE\"|\"NOTIFY\"|\"PUBLISH\"|\"MESSAGE\"|\"INFO\"|\"OPTIONS\")[ ]([^ ]*)[ ]\"SIP\"[/][0-9][.][0-9]\"\r\n\"")
   bit<1> header_req;

   @regex("\"SIP\"[/][0-9][.][0-9][ ]([0-9]*)[ ].*\"\r\n\"")
   bit<1> header_resp;

   @regex("([^:]*)\": \"(.*)\"\r\n\"")
   bit<1> sip_keyval;

   @regex("\"\r\n\"")
   bit<1> end_of_header_fields;

   @stringbuf("512") bit<1> key;
   @stringbuf("512") bit<1> val;

   @stringbuf("10") bit<1> method;
   @stringbuf("128") bit<1> uri;
   @stringbuf("10") bit<1> resp_code;

   state start {
      transition parse_header_request;
   }
   state parse_header_request {
      transition select(p.extract_re(header_req, {method, uri})) {
         true: parse_header_request_check;
         false: parse_header_response;
      }
   }
   state parse_header_request_check {
      transition select(ext.msg_type) {
         0: parse_header_request_;
         default: flush;
      }
   }
   state parse_header_request_ {
      p.strcpy(ext.request_uri, uri);
      transition check_invite;
   }

   state parse_header_response {
      transition select(p.extract_re(header_resp, resp_code)) {
         true: parse_header_response_check;
         false: reject;
      }
   }
   state parse_header_response_check {
      transition select(ext.msg_type) {
         0: parse_header_response_;
         default: flush;
      }
   }
   state parse_header_response_ {
      p.to_number(resp_code, ext.status_code);
      ext.msg_type = SIP_MSG_TYPE_STATUS;
      transition parse_fields;
   }

   state check_invite {
      @regex("\"INVITE\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_INVITE;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: check_ack;
      }
   }
   state check_ack {
      @regex("\"ACK\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_ACK;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: check_cancel;
      }
   }
   state check_cancel {
      @regex("\"CANCEL\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_CANCEL;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: check_bye;
      }
   }
   state check_bye {
      @regex("\"BYE\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_BYE;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: check_register;
      }
   }
   state check_register {
      @regex("\"REGISTER\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_REGISTER;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: check_options;
      }
   }
   state check_options {
      @regex("\"OPTIONS\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_OPTIONS;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: check_publish;
      }
   }
   state check_publish {
      @regex("\"PUBLISH\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_PUBLISH;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: check_notify;
      }
   }
   state check_notify {
      @regex("\"NOTIFY\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_NOTIFY;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: check_info;
      }
   }
   state check_info {
      @regex("\"INFO\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_INFO;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: check_subscribe;
      }
   }
   state check_subscribe {
      @regex("\"SUBSCRIBE\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_SUBSCRIBE;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: check_status;
      }
   }
   state check_status {
      @regex("\"STATUS\x00\"") bit<1> str;

      ext.msg_type = SIP_MSG_TYPE_STATUS;

      transition select(p.match(str, method)) {
         true: parse_fields;
         default: reject;
      }
   }
   state parse_fields {
      // Parse SIP header fields

      transition select(p.extract_re(sip_keyval, {key, val})) {
         true: check_from;
         false: accept;
      }
   }
   state check_from {
      @regex("\"From\x00\"")
      bit<1> str;

      transition select(p.match(str, key)) {
         true: parse_from;
         default: check_to;
      }
   }
   state parse_from {
      p.strcpy(ext.calling_party, val);
      transition parse_fields;
   }
   state check_to {
      @regex("\"To\x00\"")
      bit<1> str;

      transition select(p.match(str, key)) {
         true: parse_to;
         default: check_via;
      }
   }
   state parse_to {
      p.strcpy(ext.called_party, val);
      transition parse_fields;
   }
   state check_via {
      @regex("\"Via\x00\"")
      bit<1> str;

      transition select(p.match(str, key)) {
         true: parse_via;
         default: check_callid;
      }
   }
   state parse_via {
      p.strcpy(ext.via, val);
      transition parse_fields;
   }
   state check_callid {
      @regex("\"Call-ID\x00\"")
      bit<1> str;

      transition select(p.match(str, key)) {
         true: parse_callid;
         default: check_useragent;
      }
   }
   state parse_callid {
      p.strcpy(ext.call_id, val);
      transition parse_fields;
   }
   state check_useragent {
      @regex("\"User-Agent\x00\"")
      bit<1> str;

      transition select(p.match(str, key)) {
         true: parse_useragent;
         default: check_cseq;
      }
   }
   state parse_useragent {
      p.strcpy(ext.user_agent, val);
      transition parse_fields;
   }
   state check_cseq {
      @regex("\"CSeq\x00\"")
      bit<1> str;

      transition select(p.match(str, key)) {
         true: parse_cseq;
         default: parse_fields;
      }
   }
   state parse_cseq {
      p.strcpy(ext.cseq, val);
      transition parse_fields;
   }
   state flush {
      transition reject;
   }
}

control sip_plugin_export(in flowrec_s flow, in sip_extension_s ext, ipfix_exporter e)
{
   apply {
      FILL_IPFIX_TEMPLATE(IPFIX_TEMPLATE_IPV4_SIP, IPFIX_TEMPLATE_IPV6_SIP);
      e.add_field(ext.msg_type);
      e.add_field(ext.status_code);
      e.add_field(ext.cseq);
      e.add_field(ext.calling_party);
      e.add_field(ext.called_party);
      e.add_field(ext.call_id);
      e.add_field(ext.user_agent);
      e.add_field(ext.request_uri);
      e.add_field(ext.via);
      e.set_finish();
   }
}

#endif
