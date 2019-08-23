/**
 * \file plugin.c
 * \date 2019
 * \author Jiri Havranek <havranek@cesnet.cz>
 */
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

#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "cache.h"
#include "regex.h"
#include "plugin.h"


static struct http_extension_s *http_ext = NULL;

int parser_http_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len, struct http_extension_s *ext)
{ 
   const uint8_t *payload_end = payload + payload_len;
   (void) payload_end;
   uint8_t key_0[512];
   key_0[0] = 0;
   uint8_t val_0[512];
   val_0[0] = 0;
   uint8_t method_0[10];
   method_0[0] = 0;
   uint8_t uri_0[128];
   uri_0[0] = 0;
   uint8_t resp_code_0[10];
   resp_code_0[0] = 0;
   uint8_t tmp_29;
   uint8_t tmp_30;
   uint8_t tmp_31;
   uint8_t tmp_32;
   uint8_t tmp_33;
   uint8_t tmp_34;
   uint8_t tmp_35;
   uint8_t tmp_36;
   goto start;
   goto accept;
   goto reject;
   start: {
      tmp_29 = regex_http_292902314824198396(payload, payload_end, &payload, method_0, sizeof(method_0), uri_0, sizeof(uri_0));
      switch ((uint8_t)(tmp_29)) {
         case 1: goto parse_header_request_check;
         case 0: goto parse_header_response;
      }
      goto reject;
   }
   parse_header_response: {
      tmp_30 = regex_http_7657090775701301247(payload, payload_end, &payload, resp_code_0, sizeof(resp_code_0));
      switch ((uint8_t)(tmp_30)) {
         case 1: goto parse_header_response_check;
         case 0: goto reject;
      }
      goto reject;
   }
   parse_header_request_check: {
      switch (ext[0].type) {
         case 0: goto parse_header_request_;
         default: goto flush;
      }
      goto reject;
   }
   parse_header_request_: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.req.method) - 1 && method_0[i_]; i_++) {
            ext[0].data.req.method[i_] = method_0[i_];
         }
         ext[0].data.req.method[i_] = 0;
      }
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.req.uri) - 1 && uri_0[i_]; i_++) {
            ext[0].data.req.uri[i_] = uri_0[i_];
         }
         ext[0].data.req.uri[i_] = 0;
      }
      ext[0].type = 1;
      goto parse_fields_request;
   }
   parse_header_response_check: {
      switch (ext[0].type) {
         case 0: goto parse_header_response_;
         default: goto flush;
      }
      goto reject;
   }
   parse_header_response_: {
      ext[0].data.resp.code = strtoull((const char *) resp_code_0, NULL, 0);
      ext[0].type = 2;
      goto parse_fields_response;
   }
   parse_fields_request: {
      tmp_31 = regex_http_9954629388999303388(payload, payload_end, &payload, key_0, sizeof(key_0), val_0, sizeof(val_0));
      switch ((uint8_t)(tmp_31)) {
         case 1: goto check_host;
         case 0: goto accept;
      }
      goto reject;
   }
   check_host: {
      tmp_32 = regex_http_1241343039152043351(key_0, key_0 + sizeof(key_0), NULL);
      switch ((uint8_t)(tmp_32)) {
         case 1: goto parse_host;
         default: goto check_agent;
      }
      goto reject;
   }
   check_agent: {
      tmp_33 = regex_http_5218521091908217587(key_0, key_0 + sizeof(key_0), NULL);
      switch ((uint8_t)(tmp_33)) {
         case 1: goto parse_agent;
         default: goto check_referer;
      }
      goto reject;
   }
   check_referer: {
      tmp_34 = regex_http_4336421465629048412(key_0, key_0 + sizeof(key_0), NULL);
      switch ((uint8_t)(tmp_34)) {
         case 1: goto parse_referer;
         default: goto parse_fields_request;
      }
      goto reject;
   }
   parse_host: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.req.host) - 1 && val_0[i_]; i_++) {
            ext[0].data.req.host[i_] = val_0[i_];
         }
         ext[0].data.req.host[i_] = 0;
      }
      goto parse_fields_request;
   }
   parse_agent: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.req.agent) - 1 && val_0[i_]; i_++) {
            ext[0].data.req.agent[i_] = val_0[i_];
         }
         ext[0].data.req.agent[i_] = 0;
      }
      goto parse_fields_request;
   }
   parse_referer: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.req.referer) - 1 && val_0[i_]; i_++) {
            ext[0].data.req.referer[i_] = val_0[i_];
         }
         ext[0].data.req.referer[i_] = 0;
      }
      goto parse_fields_request;
   }
   parse_fields_response: {
      tmp_35 = regex_http_9954629388999303388(payload, payload_end, &payload, key_0, sizeof(key_0), val_0, sizeof(val_0));
      switch ((uint8_t)(tmp_35)) {
         case 1: goto extract_fields_response;
         case 0: goto accept;
      }
      goto reject;
   }
   extract_fields_response: {
      tmp_36 = regex_http_17001630350588684875(key_0, key_0 + sizeof(key_0), NULL);
      switch ((uint8_t)(tmp_36)) {
         case 1: goto parse_content;
         default: goto parse_fields_response;
      }
      goto reject;
   }
   parse_content: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.resp.content_type) - 1 && val_0[i_]; i_++) {
            ext[0].data.resp.content_type[i_] = val_0[i_];
         }
         ext[0].data.resp.content_type[i_] = 0;
      }
      goto parse_fields_response;
   }
   flush: {
      return resultFlush;
   }
   accept: {
      return resultAccept;
   }
   reject: {
      return resultReject;
   }
   return resultReject;
}
int parser_http_update(struct flowrec_s *flow, const uint8_t *payload, int payload_len, struct http_extension_s *ext)
{ 
   const uint8_t *payload_end = payload + payload_len;
   (void) payload_end;
   uint8_t key_0[512];
   key_0[0] = 0;
   uint8_t val_0[512];
   val_0[0] = 0;
   uint8_t method_0[10];
   method_0[0] = 0;
   uint8_t uri_0[128];
   uri_0[0] = 0;
   uint8_t resp_code_0[10];
   resp_code_0[0] = 0;
   uint8_t tmp_29;
   uint8_t tmp_30;
   uint8_t tmp_31;
   uint8_t tmp_32;
   uint8_t tmp_33;
   uint8_t tmp_34;
   uint8_t tmp_35;
   uint8_t tmp_36;
   goto start;
   goto accept;
   goto reject;
   start: {
      tmp_29 = regex_http_292902314824198396(payload, payload_end, &payload, method_0, sizeof(method_0), uri_0, sizeof(uri_0));
      switch ((uint8_t)(tmp_29)) {
         case 1: goto parse_header_request_check;
         case 0: goto parse_header_response;
      }
      goto reject;
   }
   parse_header_response: {
      tmp_30 = regex_http_7657090775701301247(payload, payload_end, &payload, resp_code_0, sizeof(resp_code_0));
      switch ((uint8_t)(tmp_30)) {
         case 1: goto parse_header_response_check;
         case 0: goto reject;
      }
      goto reject;
   }
   parse_header_request_check: {
      switch (ext[0].type) {
         case 0: goto parse_header_request_;
         default: goto flush;
      }
      goto reject;
   }
   parse_header_request_: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.req.method) - 1 && method_0[i_]; i_++) {
            ext[0].data.req.method[i_] = method_0[i_];
         }
         ext[0].data.req.method[i_] = 0;
      }
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.req.uri) - 1 && uri_0[i_]; i_++) {
            ext[0].data.req.uri[i_] = uri_0[i_];
         }
         ext[0].data.req.uri[i_] = 0;
      }
      ext[0].type = 1;
      goto parse_fields_request;
   }
   parse_header_response_check: {
      switch (ext[0].type) {
         case 0: goto parse_header_response_;
         default: goto flush;
      }
      goto reject;
   }
   parse_header_response_: {
      ext[0].data.resp.code = strtoull((const char *) resp_code_0, NULL, 0);
      ext[0].type = 2;
      goto parse_fields_response;
   }
   parse_fields_request: {
      tmp_31 = regex_http_9954629388999303388(payload, payload_end, &payload, key_0, sizeof(key_0), val_0, sizeof(val_0));
      switch ((uint8_t)(tmp_31)) {
         case 1: goto check_host;
         case 0: goto accept;
      }
      goto reject;
   }
   check_host: {
      tmp_32 = regex_http_1241343039152043351(key_0, key_0 + sizeof(key_0), NULL);
      switch ((uint8_t)(tmp_32)) {
         case 1: goto parse_host;
         default: goto check_agent;
      }
      goto reject;
   }
   check_agent: {
      tmp_33 = regex_http_5218521091908217587(key_0, key_0 + sizeof(key_0), NULL);
      switch ((uint8_t)(tmp_33)) {
         case 1: goto parse_agent;
         default: goto check_referer;
      }
      goto reject;
   }
   check_referer: {
      tmp_34 = regex_http_4336421465629048412(key_0, key_0 + sizeof(key_0), NULL);
      switch ((uint8_t)(tmp_34)) {
         case 1: goto parse_referer;
         default: goto parse_fields_request;
      }
      goto reject;
   }
   parse_host: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.req.host) - 1 && val_0[i_]; i_++) {
            ext[0].data.req.host[i_] = val_0[i_];
         }
         ext[0].data.req.host[i_] = 0;
      }
      goto parse_fields_request;
   }
   parse_agent: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.req.agent) - 1 && val_0[i_]; i_++) {
            ext[0].data.req.agent[i_] = val_0[i_];
         }
         ext[0].data.req.agent[i_] = 0;
      }
      goto parse_fields_request;
   }
   parse_referer: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.req.referer) - 1 && val_0[i_]; i_++) {
            ext[0].data.req.referer[i_] = val_0[i_];
         }
         ext[0].data.req.referer[i_] = 0;
      }
      goto parse_fields_request;
   }
   parse_fields_response: {
      tmp_35 = regex_http_9954629388999303388(payload, payload_end, &payload, key_0, sizeof(key_0), val_0, sizeof(val_0));
      switch ((uint8_t)(tmp_35)) {
         case 1: goto extract_fields_response;
         case 0: goto accept;
      }
      goto reject;
   }
   extract_fields_response: {
      tmp_36 = regex_http_17001630350588684875(key_0, key_0 + sizeof(key_0), NULL);
      switch ((uint8_t)(tmp_36)) {
         case 1: goto parse_content;
         default: goto parse_fields_response;
      }
      goto reject;
   }
   parse_content: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].data.resp.content_type) - 1 && val_0[i_]; i_++) {
            ext[0].data.resp.content_type[i_] = val_0[i_];
         }
         ext[0].data.resp.content_type[i_] = 0;
      }
      goto parse_fields_response;
   }
   flush: {
      return resultFlush;
   }
   accept: {
      return resultAccept;
   }
   reject: {
      return resultReject;
   }
   return resultReject;
}

int http_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len)
{
   if (http_ext == NULL) {
      http_ext = (struct http_extension_s *) malloc(sizeof(struct http_extension_s));
      memset(http_ext, 0, sizeof(struct http_extension_s));
   }

   int ret = parser_http_create(flow, payload, payload_len, http_ext);
   if (ret == resultAccept) {
      flow_add_extension(flow, http_ext, flow_ext_http);
      http_ext = NULL;
      return 0;
   } else if (ret == resultFlush) {
      flow_add_extension(flow, http_ext, flow_ext_http);
      http_ext = NULL;
      return FLOW_FLUSH;
   } else if (ret == resultExport) {
      return FLOW_EXPORT;
   }

   return 0;
}
int http_update(struct flowrec_s *flow, const uint8_t *payload, int payload_len)
{
   if (http_ext == NULL) {
      http_ext = (struct http_extension_s *) malloc(sizeof(struct http_extension_s));
      memset(http_ext, 0, sizeof(struct http_extension_s));
   }

   struct http_extension_s *ext = http_ext;
   int updateFlow = flow_get_extension(flow, (void **) &ext, flow_ext_http);

   int ret = parser_http_update(flow, payload, payload_len, ext);
   if (ret == resultAccept) {
      if (!updateFlow) {
         flow_add_extension(flow, ext, flow_ext_http);
         http_ext = NULL;
      }
      return 0;
   } else if (ret == resultFlush) {
      return FLOW_FLUSH;
   }

   return 0;
}

static struct smtp_extension_s *smtp_ext = NULL;

int parser_smtp_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len, struct smtp_extension_s *ext)
{ 
   const uint8_t *payload_end = payload + payload_len;
   (void) payload_end;
   uint8_t command_0[9];
   command_0[0] = 0;
   uint8_t dummy_0[1];
   dummy_0[0] = 0;
   uint8_t code_0[4];
   code_0[0] = 0;
   uint8_t delim_0[2];
   delim_0[0] = 0;
   uint16_t code_number_0;
   uint8_t tmp_37;
   uint8_t tmp_38;
   uint8_t tmp_39;
   uint8_t tmp_40;
   uint8_t tmp_41;
   uint8_t tmp_42;
   uint8_t tmp_43;
   uint8_t tmp_44;
   uint8_t tmp_45;
   uint8_t tmp_46;
   uint8_t tmp_47;
   uint8_t tmp_48;
   uint8_t tmp_49;
   uint8_t tmp_50;
   uint8_t tmp_51;
   uint8_t tmp_52;
   uint8_t tmp_53;
   uint8_t tmp_54;
   uint8_t tmp_55;
   uint8_t tmp_56;
   uint8_t tmp_57;
   uint8_t tmp_58;
   uint8_t tmp_59;
   uint8_t tmp_60;
   uint8_t tmp_61;
   goto start;
   goto accept;
   goto reject;
   start: {
      switch (flow[0].src_port) {
         case 25: goto check_data_transfer_;
         default: goto check_dport;
      }
      goto reject;
   }
   check_dport: {
      switch (flow[0].dst_port) {
         case 25: goto check_data_transfer_;
         default: goto reject;
      }
      goto reject;
   }
   check_data_transfer_: {
      switch (ext[0].data_transfer) {
         case 1: goto check_data_transfer;
         default: goto parse_smtp_command;
      }
      goto reject;
   }
   check_data_transfer: {
      tmp_37 = regex_smtp_5548172357307236377(payload, payload_end, &payload);
      switch ((uint8_t)(tmp_37)) {
         case 1: goto end_transfer;
         default: goto reject;
      }
      goto reject;
   }
   end_transfer: {
      ext[0].data_transfer = 0;
      goto accept;
   }
   parse_smtp_command: {
      tmp_38 = regex_smtp_1003745245910973155(payload, payload_end, &payload, command_0, sizeof(command_0), dummy_0, sizeof(dummy_0));
      switch ((uint8_t)(tmp_38)) {
         case 1: goto parse_smtp_command_;
         default: goto parse_smtp_response;
      }
      goto reject;
   }
   parse_smtp_response: {
      tmp_39 = regex_smtp_17189877207089016410(payload, payload_end, &payload, code_0, sizeof(code_0), delim_0, sizeof(delim_0));
      switch ((uint8_t)(tmp_39)) {
         case 1: goto parse_smtp_response_;
         default: goto reject;
      }
      goto reject;
   }
   parse_smtp_command_: {
      tmp_40 = regex_smtp_17179810292168586240(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_40)) {
         case 1: goto process_helo;
         default: goto check_ehlo;
      }
      goto reject;
   }
   check_ehlo: {
      tmp_41 = regex_smtp_8038746631168771053(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_41)) {
         case 1: goto process_ehlo;
         default: goto check_rcpt;
      }
      goto reject;
   }
   process_helo: {
      ext[0].command_flags = (ext[0].command_flags) | (2);
      tmp_42 = regex_smtp_1491806206036761928(ext[0].domain, ext[0].domain + sizeof(ext[0].domain), NULL);
      switch ((uint8_t)(tmp_42)) {
         case 1: goto parse_domain;
         default: goto accept;
      }
      goto reject;
   }
   process_ehlo: {
      ext[0].command_flags = (ext[0].command_flags) | (1);
      tmp_43 = regex_smtp_1491806206036761928(ext[0].domain, ext[0].domain + sizeof(ext[0].domain), NULL);
      switch ((uint8_t)(tmp_43)) {
         case 1: goto parse_domain;
         default: goto accept;
      }
      goto reject;
   }
   parse_domain: {
      tmp_44 = regex_smtp_16043735937296782989(payload, payload_end, &payload, ext[0].domain, sizeof(ext[0].domain));
      switch ((uint8_t)(tmp_44)) {
         default: goto accept;
      }
      goto reject;
   }
   check_rcpt: {
      tmp_45 = regex_smtp_12378696050549599547(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_45)) {
         case 1: goto process_rcpt;
         default: goto check_mail;
      }
      goto reject;
   }
   process_rcpt: {
      ext[0].mail_rcpt_cnt = (ext[0].mail_rcpt_cnt) + (1);
      ext[0].command_flags = (ext[0].command_flags) | (8);
      tmp_46 = regex_smtp_1491806206036761928(ext[0].first_recipient, ext[0].first_recipient + sizeof(ext[0].first_recipient), NULL);
      switch ((uint8_t)(tmp_46)) {
         case 1: goto parse_rcpt;
         default: goto accept;
      }
      goto reject;
   }
   parse_rcpt: {
      tmp_47 = regex_smtp_10049501445715452691(payload, payload_end, &payload, ext[0].first_recipient, sizeof(ext[0].first_recipient));
      switch ((uint8_t)(tmp_47)) {
         default: goto accept;
      }
      goto reject;
   }
   check_mail: {
      tmp_48 = regex_smtp_16154841742982731464(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_48)) {
         case 1: goto process_mail;
         default: goto check_data;
      }
      goto reject;
   }
   process_mail: {
      ext[0].mail_cmd_cnt = (ext[0].mail_cmd_cnt) + (1);
      ext[0].command_flags = (ext[0].command_flags) | (4);
      tmp_49 = regex_smtp_1491806206036761928(ext[0].first_sender, ext[0].first_sender + sizeof(ext[0].first_sender), NULL);
      switch ((uint8_t)(tmp_49)) {
         case 1: goto parse_mail;
         default: goto accept;
      }
      goto reject;
   }
   parse_mail: {
      tmp_50 = regex_smtp_2926034056909831890(payload, payload_end, &payload, ext[0].first_sender, sizeof(ext[0].first_sender));
      switch ((uint8_t)(tmp_50)) {
         default: goto accept;
      }
      goto reject;
   }
   check_data: {
      tmp_51 = regex_smtp_4356961479564686332(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_51)) {
         case 1: goto process_data;
         default: goto check_vrfy;
      }
      goto reject;
   }
   process_data: {
      ext[0].command_flags = (ext[0].command_flags) | (16);
      ext[0].data_transfer = 1;
      goto accept;
   }
   check_vrfy: {
      tmp_52 = regex_smtp_6311271132146768079(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_52)) {
         case 1: goto process_vrfy;
         default: goto check_expn;
      }
      goto reject;
   }
   process_vrfy: {
      ext[0].command_flags = (ext[0].command_flags) | (64);
      goto accept;
   }
   check_expn: {
      tmp_53 = regex_smtp_15599524012596978294(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_53)) {
         case 1: goto process_expn;
         default: goto check_help;
      }
      goto reject;
   }
   process_expn: {
      ext[0].command_flags = (ext[0].command_flags) | (128);
      goto accept;
   }
   check_help: {
      tmp_54 = regex_smtp_319042037054728586(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_54)) {
         case 1: goto process_help;
         default: goto check_noop;
      }
      goto reject;
   }
   process_help: {
      ext[0].command_flags = (ext[0].command_flags) | (256);
      goto accept;
   }
   check_noop: {
      tmp_55 = regex_smtp_4162994491442343091(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_55)) {
         case 1: goto process_noop;
         default: goto check_quit;
      }
      goto reject;
   }
   process_noop: {
      ext[0].command_flags = (ext[0].command_flags) | (512);
      goto accept;
   }
   check_quit: {
      tmp_56 = regex_smtp_17596464307372590331(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_56)) {
         case 1: goto process_quit;
         default: goto process_unknown_command;
      }
      goto reject;
   }
   process_quit: {
      ext[0].command_flags = (ext[0].command_flags) | (1024);
      goto accept;
   }
   process_unknown_command: {
      ext[0].command_flags = (ext[0].command_flags) | (32768);
      goto accept;
   }
   parse_smtp_response_: {
      code_number_0 = strtoull((const char *) code_0, NULL, 0);
      switch (code_number_0) {
         case 211: goto process_211;
         case 214: goto process_214;
         case 220: goto process_220;
         case 221: goto process_221;
         case 250: goto process_250;
         case 251: goto process_251;
         case 252: goto process_252;
         case 354: goto process_354;
         case 421: goto process_421;
         case 450: goto process_450;
         case 451: goto process_451;
         case 452: goto process_452;
         case 455: goto process_455;
         case 500: goto process_500;
         case 501: goto process_501;
         case 502: goto process_502;
         case 503: goto process_503;
         case 504: goto process_504;
         case 550: goto process_550;
         case 551: goto process_551;
         case 552: goto process_552;
         case 553: goto process_553;
         case 554: goto process_554;
         case 555: goto process_555;
         default: goto process_unknown_code;
      }
      goto reject;
   }
   process_211: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (1);
      goto check_response_2xx;
   }
   process_214: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (2);
      goto check_response_2xx;
   }
   process_220: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (4);
      goto check_response_2xx;
   }
   process_221: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (8);
      goto check_response_2xx;
   }
   process_250: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (16);
      goto check_response_2xx;
   }
   process_251: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (32);
      goto check_response_2xx;
   }
   process_252: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (64);
      goto check_response_2xx;
   }
   process_354: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (128);
      goto check_response_2xx;
   }
   process_421: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (256);
      goto check_response_2xx;
   }
   process_450: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (512);
      goto check_response_2xx;
   }
   process_451: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (1024);
      goto check_response_2xx;
   }
   process_452: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (2048);
      goto check_response_2xx;
   }
   process_455: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (4096);
      goto check_response_2xx;
   }
   process_500: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (8192);
      goto check_response_2xx;
   }
   process_501: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (16384);
      goto check_response_2xx;
   }
   process_502: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (32768);
      goto check_response_2xx;
   }
   process_503: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (65536);
      goto check_response_2xx;
   }
   process_504: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (131072);
      goto check_response_2xx;
   }
   process_550: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (262144);
      goto check_response_2xx;
   }
   process_551: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (524288);
      goto check_response_2xx;
   }
   process_552: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (1048576);
      goto check_response_2xx;
   }
   process_553: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (2097152);
      goto check_response_2xx;
   }
   process_554: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (4194304);
      goto check_response_2xx;
   }
   process_555: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (8388608);
      goto check_response_2xx;
   }
   process_unknown_code: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (2147483648);
      goto check_response_2xx;
   }
   check_response_2xx: {
      tmp_57 = regex_smtp_10389749760020421673(code_0, code_0 + sizeof(code_0), NULL);
      switch ((uint8_t)(tmp_57)) {
         case 1: goto process_response_2xx;
         default: goto check_response_3xx;
      }
      goto reject;
   }
   process_response_2xx: {
      ext[0].code_2xx_cnt = (ext[0].code_2xx_cnt) + (1);
      goto check_spam;
   }
   check_response_3xx: {
      tmp_58 = regex_smtp_14714683673343533196(code_0, code_0 + sizeof(code_0), NULL);
      switch ((uint8_t)(tmp_58)) {
         case 1: goto process_response_3xx;
         default: goto check_response_4xx;
      }
      goto reject;
   }
   process_response_3xx: {
      ext[0].code_3xx_cnt = (ext[0].code_3xx_cnt) + (1);
      goto check_spam;
   }
   check_response_4xx: {
      tmp_59 = regex_smtp_7033087601884999626(code_0, code_0 + sizeof(code_0), NULL);
      switch ((uint8_t)(tmp_59)) {
         case 1: goto process_response_4xx;
         default: goto check_response_5xx;
      }
      goto reject;
   }
   process_response_4xx: {
      ext[0].code_4xx_cnt = (ext[0].code_4xx_cnt) + (1);
      goto check_spam;
   }
   check_response_5xx: {
      tmp_60 = regex_smtp_11669751789635211030(code_0, code_0 + sizeof(code_0), NULL);
      switch ((uint8_t)(tmp_60)) {
         case 1: goto process_response_5xx;
         default: goto check_spam;
      }
      goto reject;
   }
   process_response_5xx: {
      ext[0].code_5xx_cnt = (ext[0].code_5xx_cnt) + (1);
      goto check_spam;
   }
   check_spam: {
      tmp_61 = regex_smtp_5915433088431825607(payload, payload_end, &payload);
      switch ((uint8_t)(tmp_61)) {
         case 1: goto process_spam;
         default: goto accept;
      }
      goto reject;
   }
   process_spam: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (1073741824);
      goto accept;
   }
   accept: {
      return resultAccept;
   }
   reject: {
      return resultReject;
   }
   return resultReject;
}
int parser_smtp_update(struct flowrec_s *flow, const uint8_t *payload, int payload_len, struct smtp_extension_s *ext)
{ 
   const uint8_t *payload_end = payload + payload_len;
   (void) payload_end;
   uint8_t command_0[9];
   command_0[0] = 0;
   uint8_t dummy_0[1];
   dummy_0[0] = 0;
   uint8_t code_0[4];
   code_0[0] = 0;
   uint8_t delim_0[2];
   delim_0[0] = 0;
   uint16_t code_number_0;
   uint8_t tmp_37;
   uint8_t tmp_38;
   uint8_t tmp_39;
   uint8_t tmp_40;
   uint8_t tmp_41;
   uint8_t tmp_42;
   uint8_t tmp_43;
   uint8_t tmp_44;
   uint8_t tmp_45;
   uint8_t tmp_46;
   uint8_t tmp_47;
   uint8_t tmp_48;
   uint8_t tmp_49;
   uint8_t tmp_50;
   uint8_t tmp_51;
   uint8_t tmp_52;
   uint8_t tmp_53;
   uint8_t tmp_54;
   uint8_t tmp_55;
   uint8_t tmp_56;
   uint8_t tmp_57;
   uint8_t tmp_58;
   uint8_t tmp_59;
   uint8_t tmp_60;
   uint8_t tmp_61;
   goto start;
   goto accept;
   goto reject;
   start: {
      switch (flow[0].src_port) {
         case 25: goto check_data_transfer_;
         default: goto check_dport;
      }
      goto reject;
   }
   check_dport: {
      switch (flow[0].dst_port) {
         case 25: goto check_data_transfer_;
         default: goto reject;
      }
      goto reject;
   }
   check_data_transfer_: {
      switch (ext[0].data_transfer) {
         case 1: goto check_data_transfer;
         default: goto parse_smtp_command;
      }
      goto reject;
   }
   check_data_transfer: {
      tmp_37 = regex_smtp_5548172357307236377(payload, payload_end, &payload);
      switch ((uint8_t)(tmp_37)) {
         case 1: goto end_transfer;
         default: goto reject;
      }
      goto reject;
   }
   end_transfer: {
      ext[0].data_transfer = 0;
      goto accept;
   }
   parse_smtp_command: {
      tmp_38 = regex_smtp_1003745245910973155(payload, payload_end, &payload, command_0, sizeof(command_0), dummy_0, sizeof(dummy_0));
      switch ((uint8_t)(tmp_38)) {
         case 1: goto parse_smtp_command_;
         default: goto parse_smtp_response;
      }
      goto reject;
   }
   parse_smtp_response: {
      tmp_39 = regex_smtp_17189877207089016410(payload, payload_end, &payload, code_0, sizeof(code_0), delim_0, sizeof(delim_0));
      switch ((uint8_t)(tmp_39)) {
         case 1: goto parse_smtp_response_;
         default: goto reject;
      }
      goto reject;
   }
   parse_smtp_command_: {
      tmp_40 = regex_smtp_17179810292168586240(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_40)) {
         case 1: goto process_helo;
         default: goto check_ehlo;
      }
      goto reject;
   }
   check_ehlo: {
      tmp_41 = regex_smtp_8038746631168771053(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_41)) {
         case 1: goto process_ehlo;
         default: goto check_rcpt;
      }
      goto reject;
   }
   process_helo: {
      ext[0].command_flags = (ext[0].command_flags) | (2);
      tmp_42 = regex_smtp_1491806206036761928(ext[0].domain, ext[0].domain + sizeof(ext[0].domain), NULL);
      switch ((uint8_t)(tmp_42)) {
         case 1: goto parse_domain;
         default: goto accept;
      }
      goto reject;
   }
   process_ehlo: {
      ext[0].command_flags = (ext[0].command_flags) | (1);
      tmp_43 = regex_smtp_1491806206036761928(ext[0].domain, ext[0].domain + sizeof(ext[0].domain), NULL);
      switch ((uint8_t)(tmp_43)) {
         case 1: goto parse_domain;
         default: goto accept;
      }
      goto reject;
   }
   parse_domain: {
      tmp_44 = regex_smtp_16043735937296782989(payload, payload_end, &payload, ext[0].domain, sizeof(ext[0].domain));
      switch ((uint8_t)(tmp_44)) {
         default: goto accept;
      }
      goto reject;
   }
   check_rcpt: {
      tmp_45 = regex_smtp_12378696050549599547(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_45)) {
         case 1: goto process_rcpt;
         default: goto check_mail;
      }
      goto reject;
   }
   process_rcpt: {
      ext[0].mail_rcpt_cnt = (ext[0].mail_rcpt_cnt) + (1);
      ext[0].command_flags = (ext[0].command_flags) | (8);
      tmp_46 = regex_smtp_1491806206036761928(ext[0].first_recipient, ext[0].first_recipient + sizeof(ext[0].first_recipient), NULL);
      switch ((uint8_t)(tmp_46)) {
         case 1: goto parse_rcpt;
         default: goto accept;
      }
      goto reject;
   }
   parse_rcpt: {
      tmp_47 = regex_smtp_10049501445715452691(payload, payload_end, &payload, ext[0].first_recipient, sizeof(ext[0].first_recipient));
      switch ((uint8_t)(tmp_47)) {
         default: goto accept;
      }
      goto reject;
   }
   check_mail: {
      tmp_48 = regex_smtp_16154841742982731464(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_48)) {
         case 1: goto process_mail;
         default: goto check_data;
      }
      goto reject;
   }
   process_mail: {
      ext[0].mail_cmd_cnt = (ext[0].mail_cmd_cnt) + (1);
      ext[0].command_flags = (ext[0].command_flags) | (4);
      tmp_49 = regex_smtp_1491806206036761928(ext[0].first_sender, ext[0].first_sender + sizeof(ext[0].first_sender), NULL);
      switch ((uint8_t)(tmp_49)) {
         case 1: goto parse_mail;
         default: goto accept;
      }
      goto reject;
   }
   parse_mail: {
      tmp_50 = regex_smtp_2926034056909831890(payload, payload_end, &payload, ext[0].first_sender, sizeof(ext[0].first_sender));
      switch ((uint8_t)(tmp_50)) {
         default: goto accept;
      }
      goto reject;
   }
   check_data: {
      tmp_51 = regex_smtp_4356961479564686332(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_51)) {
         case 1: goto process_data;
         default: goto check_vrfy;
      }
      goto reject;
   }
   process_data: {
      ext[0].command_flags = (ext[0].command_flags) | (16);
      ext[0].data_transfer = 1;
      goto accept;
   }
   check_vrfy: {
      tmp_52 = regex_smtp_6311271132146768079(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_52)) {
         case 1: goto process_vrfy;
         default: goto check_expn;
      }
      goto reject;
   }
   process_vrfy: {
      ext[0].command_flags = (ext[0].command_flags) | (64);
      goto accept;
   }
   check_expn: {
      tmp_53 = regex_smtp_15599524012596978294(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_53)) {
         case 1: goto process_expn;
         default: goto check_help;
      }
      goto reject;
   }
   process_expn: {
      ext[0].command_flags = (ext[0].command_flags) | (128);
      goto accept;
   }
   check_help: {
      tmp_54 = regex_smtp_319042037054728586(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_54)) {
         case 1: goto process_help;
         default: goto check_noop;
      }
      goto reject;
   }
   process_help: {
      ext[0].command_flags = (ext[0].command_flags) | (256);
      goto accept;
   }
   check_noop: {
      tmp_55 = regex_smtp_4162994491442343091(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_55)) {
         case 1: goto process_noop;
         default: goto check_quit;
      }
      goto reject;
   }
   process_noop: {
      ext[0].command_flags = (ext[0].command_flags) | (512);
      goto accept;
   }
   check_quit: {
      tmp_56 = regex_smtp_17596464307372590331(command_0, command_0 + sizeof(command_0), NULL);
      switch ((uint8_t)(tmp_56)) {
         case 1: goto process_quit;
         default: goto process_unknown_command;
      }
      goto reject;
   }
   process_quit: {
      ext[0].command_flags = (ext[0].command_flags) | (1024);
      goto accept;
   }
   process_unknown_command: {
      ext[0].command_flags = (ext[0].command_flags) | (32768);
      goto accept;
   }
   parse_smtp_response_: {
      code_number_0 = strtoull((const char *) code_0, NULL, 0);
      switch (code_number_0) {
         case 211: goto process_211;
         case 214: goto process_214;
         case 220: goto process_220;
         case 221: goto process_221;
         case 250: goto process_250;
         case 251: goto process_251;
         case 252: goto process_252;
         case 354: goto process_354;
         case 421: goto process_421;
         case 450: goto process_450;
         case 451: goto process_451;
         case 452: goto process_452;
         case 455: goto process_455;
         case 500: goto process_500;
         case 501: goto process_501;
         case 502: goto process_502;
         case 503: goto process_503;
         case 504: goto process_504;
         case 550: goto process_550;
         case 551: goto process_551;
         case 552: goto process_552;
         case 553: goto process_553;
         case 554: goto process_554;
         case 555: goto process_555;
         default: goto process_unknown_code;
      }
      goto reject;
   }
   process_211: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (1);
      goto check_response_2xx;
   }
   process_214: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (2);
      goto check_response_2xx;
   }
   process_220: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (4);
      goto check_response_2xx;
   }
   process_221: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (8);
      goto check_response_2xx;
   }
   process_250: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (16);
      goto check_response_2xx;
   }
   process_251: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (32);
      goto check_response_2xx;
   }
   process_252: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (64);
      goto check_response_2xx;
   }
   process_354: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (128);
      goto check_response_2xx;
   }
   process_421: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (256);
      goto check_response_2xx;
   }
   process_450: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (512);
      goto check_response_2xx;
   }
   process_451: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (1024);
      goto check_response_2xx;
   }
   process_452: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (2048);
      goto check_response_2xx;
   }
   process_455: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (4096);
      goto check_response_2xx;
   }
   process_500: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (8192);
      goto check_response_2xx;
   }
   process_501: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (16384);
      goto check_response_2xx;
   }
   process_502: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (32768);
      goto check_response_2xx;
   }
   process_503: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (65536);
      goto check_response_2xx;
   }
   process_504: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (131072);
      goto check_response_2xx;
   }
   process_550: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (262144);
      goto check_response_2xx;
   }
   process_551: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (524288);
      goto check_response_2xx;
   }
   process_552: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (1048576);
      goto check_response_2xx;
   }
   process_553: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (2097152);
      goto check_response_2xx;
   }
   process_554: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (4194304);
      goto check_response_2xx;
   }
   process_555: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (8388608);
      goto check_response_2xx;
   }
   process_unknown_code: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (2147483648);
      goto check_response_2xx;
   }
   check_response_2xx: {
      tmp_57 = regex_smtp_10389749760020421673(code_0, code_0 + sizeof(code_0), NULL);
      switch ((uint8_t)(tmp_57)) {
         case 1: goto process_response_2xx;
         default: goto check_response_3xx;
      }
      goto reject;
   }
   process_response_2xx: {
      ext[0].code_2xx_cnt = (ext[0].code_2xx_cnt) + (1);
      goto check_spam;
   }
   check_response_3xx: {
      tmp_58 = regex_smtp_14714683673343533196(code_0, code_0 + sizeof(code_0), NULL);
      switch ((uint8_t)(tmp_58)) {
         case 1: goto process_response_3xx;
         default: goto check_response_4xx;
      }
      goto reject;
   }
   process_response_3xx: {
      ext[0].code_3xx_cnt = (ext[0].code_3xx_cnt) + (1);
      goto check_spam;
   }
   check_response_4xx: {
      tmp_59 = regex_smtp_7033087601884999626(code_0, code_0 + sizeof(code_0), NULL);
      switch ((uint8_t)(tmp_59)) {
         case 1: goto process_response_4xx;
         default: goto check_response_5xx;
      }
      goto reject;
   }
   process_response_4xx: {
      ext[0].code_4xx_cnt = (ext[0].code_4xx_cnt) + (1);
      goto check_spam;
   }
   check_response_5xx: {
      tmp_60 = regex_smtp_11669751789635211030(code_0, code_0 + sizeof(code_0), NULL);
      switch ((uint8_t)(tmp_60)) {
         case 1: goto process_response_5xx;
         default: goto check_spam;
      }
      goto reject;
   }
   process_response_5xx: {
      ext[0].code_5xx_cnt = (ext[0].code_5xx_cnt) + (1);
      goto check_spam;
   }
   check_spam: {
      tmp_61 = regex_smtp_5915433088431825607(payload, payload_end, &payload);
      switch ((uint8_t)(tmp_61)) {
         case 1: goto process_spam;
         default: goto accept;
      }
      goto reject;
   }
   process_spam: {
      ext[0].mail_code_flags = (ext[0].mail_code_flags) | (1073741824);
      goto accept;
   }
   accept: {
      return resultAccept;
   }
   reject: {
      return resultReject;
   }
   return resultReject;
}

int smtp_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len)
{
   if (smtp_ext == NULL) {
      smtp_ext = (struct smtp_extension_s *) malloc(sizeof(struct smtp_extension_s));
      memset(smtp_ext, 0, sizeof(struct smtp_extension_s));
   }

   int ret = parser_smtp_create(flow, payload, payload_len, smtp_ext);
   if (ret == resultAccept) {
      flow_add_extension(flow, smtp_ext, flow_ext_smtp);
      smtp_ext = NULL;
      return 0;
   } else if (ret == resultFlush) {
      flow_add_extension(flow, smtp_ext, flow_ext_smtp);
      smtp_ext = NULL;
      return FLOW_FLUSH;
   } else if (ret == resultExport) {
      return FLOW_EXPORT;
   }

   return 0;
}
int smtp_update(struct flowrec_s *flow, const uint8_t *payload, int payload_len)
{
   if (smtp_ext == NULL) {
      smtp_ext = (struct smtp_extension_s *) malloc(sizeof(struct smtp_extension_s));
      memset(smtp_ext, 0, sizeof(struct smtp_extension_s));
   }

   struct smtp_extension_s *ext = smtp_ext;
   int updateFlow = flow_get_extension(flow, (void **) &ext, flow_ext_smtp);

   int ret = parser_smtp_update(flow, payload, payload_len, ext);
   if (ret == resultAccept) {
      if (!updateFlow) {
         flow_add_extension(flow, ext, flow_ext_smtp);
         smtp_ext = NULL;
      }
      return 0;
   } else if (ret == resultFlush) {
      return FLOW_FLUSH;
   }

   return 0;
}

static struct https_extension_s *https_ext = NULL;

int parser_https_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len, struct https_extension_s *ext)
{ 
   const uint8_t *payload_end = payload + payload_len;
   (void) payload_end;
   struct tls_rec_h tls_rec_0;
   struct tls_handshake_h tls_hs_0;
   uint16_t extensions_len_0;
   uint16_t extensions_len_parsed_0;
   struct tls_ext_h tls_ext_0;
   uint16_t sni_list_len_0;
   uint16_t sni_list_len_parsed_0;
   struct tls_ext_sni_h tls_sni_0;
   uint8_t session_id_len_0;
   uint16_t cipher_suites_len_0;
   uint8_t compression_methods_len_0;
   uint8_t tmp_62;
   goto start;
   goto accept;
   goto reject;
   start: {
      tmp_62 = regex_https_1491806206036761928(ext[0].sni, ext[0].sni + sizeof(ext[0].sni), NULL);
      switch ((uint8_t)(tmp_62)) {
         case 1: goto flush;
         default: goto check_record;
      }
      goto reject;
   }
   check_record: {
      if (payload + 5 > payload_end) { goto reject; }
      tls_rec_0.type = ((uint8_t)(load_byte(payload, 0)));
   DEBUG_MSG("tls_rec_0.type = %#02x\n", tls_rec_0.type);
      tls_rec_0.v_major = ((uint8_t)(load_byte(payload, 1)));
   DEBUG_MSG("tls_rec_0.v_major = %#02x\n", tls_rec_0.v_major);
      tls_rec_0.v_minor = ((uint8_t)(load_byte(payload, 2)));
   DEBUG_MSG("tls_rec_0.v_minor = %#02x\n", tls_rec_0.v_minor);
      tls_rec_0.length = ntohs((uint16_t)(load_half(payload, 3)));
   DEBUG_MSG("tls_rec_0.length = %#04x\n", tls_rec_0.length);
      payload += 5;
      switch (tls_rec_0.type) {
         case 22: goto check_version_1;
         default: goto reject;
      }
      goto reject;
   }
   check_version_1: {
      switch (tls_rec_0.v_major) {
         case 3: goto check_version_2;
         default: goto reject;
      }
      goto reject;
   }
   check_version_2: {
      switch (tls_rec_0.v_minor) {
         case 0: goto check_hello;
         case 1: goto check_hello;
         case 2: goto check_hello;
         case 3: goto check_hello;
         default: goto reject;
      }
      goto reject;
   }
   check_hello: {
      if (payload + 6 > payload_end) { goto reject; }
      tls_hs_0.type = ((uint8_t)(load_byte(payload, 0)));
   DEBUG_MSG("tls_hs_0.type = %#02x\n", tls_hs_0.type);
      tls_hs_0.length = (uint32_t)(ntohl(load_word(payload, 1)) >> 8) & FPP_MASK(uint32_t, 24);
   DEBUG_MSG("tls_hs_0.length = %#08x\n", tls_hs_0.length);
      tls_hs_0.v_major = ((uint8_t)(load_byte(payload, 4)));
   DEBUG_MSG("tls_hs_0.v_major = %#02x\n", tls_hs_0.v_major);
      tls_hs_0.v_minor = ((uint8_t)(load_byte(payload, 5)));
   DEBUG_MSG("tls_hs_0.v_minor = %#02x\n", tls_hs_0.v_minor);
      payload += 6;
      switch (tls_hs_0.type) {
         case 1: goto check_hello_version_1;
         default: goto reject;
      }
      goto reject;
   }
   check_hello_version_1: {
      switch (tls_hs_0.v_major) {
         case 3: goto check_hello_version_2;
         default: goto reject;
      }
      goto reject;
   }
   check_hello_version_2: {
      switch (tls_hs_0.v_minor) {
         case 1: goto skip_parameters;
         case 2: goto skip_parameters;
         case 3: goto skip_parameters;
         default: goto reject;
      }
      goto reject;
   }
   skip_parameters: {
      payload += 32;
      if (payload + 1 > payload_end) { goto reject; }
      session_id_len_0 = ((uint8_t)(load_byte(payload, 0)));
      payload += 1;
      payload += (uint32_t)(session_id_len_0);
      if (payload + 2 > payload_end) { goto reject; }
      cipher_suites_len_0 = ntohs((uint16_t)(load_half(payload, 0)));
      payload += 2;
      payload += (uint32_t)(cipher_suites_len_0);
      if (payload + 1 > payload_end) { goto reject; }
      compression_methods_len_0 = ((uint8_t)(load_byte(payload, 0)));
      payload += 1;
      payload += (uint32_t)(compression_methods_len_0);
      if (payload + 2 > payload_end) { goto reject; }
      extensions_len_0 = ntohs((uint16_t)(load_half(payload, 0)));
      payload += 2;
      extensions_len_parsed_0 = 0;
      goto parse_extensions_check;
   }
   parse_extensions_check: {
      switch ((uint8_t)(((extensions_len_parsed_0) + (4)) >= (extensions_len_0))) {
         case 1: goto reject;
         default: goto parse_extensions;
      }
      goto reject;
   }
   parse_extensions: {
      if (payload + 4 > payload_end) { goto reject; }
      tls_ext_0.type = ntohs((uint16_t)(load_half(payload, 0)));
   DEBUG_MSG("tls_ext_0.type = %#04x\n", tls_ext_0.type);
      tls_ext_0.length = ntohs((uint16_t)(load_half(payload, 2)));
   DEBUG_MSG("tls_ext_0.length = %#04x\n", tls_ext_0.length);
      payload += 4;
      switch (tls_ext_0.type) {
         case 0: goto parse_sni_check;
         default: goto parse_extensions_skip;
      }
      goto reject;
   }
   parse_extensions_skip: {
      extensions_len_parsed_0 = ((extensions_len_parsed_0) + (tls_ext_0.length)) + (4);
      payload += (uint32_t)(tls_ext_0.length);
      goto parse_extensions_check;
   }
   parse_sni_check: {
      sni_list_len_parsed_0 = 0;
      switch ((uint8_t)((tls_ext_0.length) > (2))) {
         case 1: goto parse_sni_list_;
         default: goto reject;
      }
      goto reject;
   }
   parse_sni_list_: {
      if (payload + 2 > payload_end) { goto reject; }
      sni_list_len_0 = ntohs((uint16_t)(load_half(payload, 0)));
      payload += 2;
      goto parse_sni_list_check;
   }
   parse_sni_list_check: {
      switch ((uint8_t)(((sni_list_len_parsed_0) + (3)) >= (sni_list_len_0))) {
         case 1: goto reject;
         default: goto parse_sni_list;
      }
      goto reject;
   }
   parse_sni_list: {
      if (payload + 3 > payload_end) { goto reject; }
      tls_sni_0.type = ((uint8_t)(load_byte(payload, 0)));
   DEBUG_MSG("tls_sni_0.type = %#02x\n", tls_sni_0.type);
      tls_sni_0.length = ntohs((uint16_t)(load_half(payload, 1)));
   DEBUG_MSG("tls_sni_0.length = %#04x\n", tls_sni_0.length);
      payload += 3;
      switch (tls_sni_0.type) {
         case 0: goto parse_sni_list_elem_check;
         default: goto parse_sni_list_skip;
      }
      goto reject;
   }
   parse_sni_list_skip: {
      payload += (uint32_t)(tls_sni_0.length);
      sni_list_len_parsed_0 = ((sni_list_len_parsed_0) + (tls_sni_0.length)) + (3);
      goto parse_sni_list_check;
   }
   parse_sni_list_elem_check: {
      switch ((uint8_t)((tls_sni_0.length) > (0))) {
         case 1: goto parse_sni;
         default: goto parse_sni_list_skip;
      }
      goto reject;
   }
   parse_sni: {
      if (payload + (uint32_t)(tls_sni_0.length) > payload_end) { goto reject; }
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].sni) - 1 && i_ < (uint32_t)(tls_sni_0.length); i_++) {
            ext[0].sni[i_] = payload[i_];
         }
         ext[0].sni[i_] = 0;
      }
      payload += (uint32_t)(tls_sni_0.length);
      goto accept;
   }
   flush: {
      return resultFlush;
   }
   accept: {
      return resultAccept;
   }
   reject: {
      return resultReject;
   }
   return resultReject;
}
int parser_https_update(struct flowrec_s *flow, const uint8_t *payload, int payload_len, struct https_extension_s *ext)
{ 
   const uint8_t *payload_end = payload + payload_len;
   (void) payload_end;
   struct tls_rec_h tls_rec_0;
   struct tls_handshake_h tls_hs_0;
   uint16_t extensions_len_0;
   uint16_t extensions_len_parsed_0;
   struct tls_ext_h tls_ext_0;
   uint16_t sni_list_len_0;
   uint16_t sni_list_len_parsed_0;
   struct tls_ext_sni_h tls_sni_0;
   uint8_t session_id_len_0;
   uint16_t cipher_suites_len_0;
   uint8_t compression_methods_len_0;
   uint8_t tmp_62;
   goto start;
   goto accept;
   goto reject;
   start: {
      tmp_62 = regex_https_1491806206036761928(ext[0].sni, ext[0].sni + sizeof(ext[0].sni), NULL);
      switch ((uint8_t)(tmp_62)) {
         case 1: goto flush;
         default: goto check_record;
      }
      goto reject;
   }
   check_record: {
      if (payload + 5 > payload_end) { goto reject; }
      tls_rec_0.type = ((uint8_t)(load_byte(payload, 0)));
   DEBUG_MSG("tls_rec_0.type = %#02x\n", tls_rec_0.type);
      tls_rec_0.v_major = ((uint8_t)(load_byte(payload, 1)));
   DEBUG_MSG("tls_rec_0.v_major = %#02x\n", tls_rec_0.v_major);
      tls_rec_0.v_minor = ((uint8_t)(load_byte(payload, 2)));
   DEBUG_MSG("tls_rec_0.v_minor = %#02x\n", tls_rec_0.v_minor);
      tls_rec_0.length = ntohs((uint16_t)(load_half(payload, 3)));
   DEBUG_MSG("tls_rec_0.length = %#04x\n", tls_rec_0.length);
      payload += 5;
      switch (tls_rec_0.type) {
         case 22: goto check_version_1;
         default: goto reject;
      }
      goto reject;
   }
   check_version_1: {
      switch (tls_rec_0.v_major) {
         case 3: goto check_version_2;
         default: goto reject;
      }
      goto reject;
   }
   check_version_2: {
      switch (tls_rec_0.v_minor) {
         case 0: goto check_hello;
         case 1: goto check_hello;
         case 2: goto check_hello;
         case 3: goto check_hello;
         default: goto reject;
      }
      goto reject;
   }
   check_hello: {
      if (payload + 6 > payload_end) { goto reject; }
      tls_hs_0.type = ((uint8_t)(load_byte(payload, 0)));
   DEBUG_MSG("tls_hs_0.type = %#02x\n", tls_hs_0.type);
      tls_hs_0.length = (uint32_t)(ntohl(load_word(payload, 1)) >> 8) & FPP_MASK(uint32_t, 24);
   DEBUG_MSG("tls_hs_0.length = %#08x\n", tls_hs_0.length);
      tls_hs_0.v_major = ((uint8_t)(load_byte(payload, 4)));
   DEBUG_MSG("tls_hs_0.v_major = %#02x\n", tls_hs_0.v_major);
      tls_hs_0.v_minor = ((uint8_t)(load_byte(payload, 5)));
   DEBUG_MSG("tls_hs_0.v_minor = %#02x\n", tls_hs_0.v_minor);
      payload += 6;
      switch (tls_hs_0.type) {
         case 1: goto check_hello_version_1;
         default: goto reject;
      }
      goto reject;
   }
   check_hello_version_1: {
      switch (tls_hs_0.v_major) {
         case 3: goto check_hello_version_2;
         default: goto reject;
      }
      goto reject;
   }
   check_hello_version_2: {
      switch (tls_hs_0.v_minor) {
         case 1: goto skip_parameters;
         case 2: goto skip_parameters;
         case 3: goto skip_parameters;
         default: goto reject;
      }
      goto reject;
   }
   skip_parameters: {
      payload += 32;
      if (payload + 1 > payload_end) { goto reject; }
      session_id_len_0 = ((uint8_t)(load_byte(payload, 0)));
      payload += 1;
      payload += (uint32_t)(session_id_len_0);
      if (payload + 2 > payload_end) { goto reject; }
      cipher_suites_len_0 = ntohs((uint16_t)(load_half(payload, 0)));
      payload += 2;
      payload += (uint32_t)(cipher_suites_len_0);
      if (payload + 1 > payload_end) { goto reject; }
      compression_methods_len_0 = ((uint8_t)(load_byte(payload, 0)));
      payload += 1;
      payload += (uint32_t)(compression_methods_len_0);
      if (payload + 2 > payload_end) { goto reject; }
      extensions_len_0 = ntohs((uint16_t)(load_half(payload, 0)));
      payload += 2;
      extensions_len_parsed_0 = 0;
      goto parse_extensions_check;
   }
   parse_extensions_check: {
      switch ((uint8_t)(((extensions_len_parsed_0) + (4)) >= (extensions_len_0))) {
         case 1: goto reject;
         default: goto parse_extensions;
      }
      goto reject;
   }
   parse_extensions: {
      if (payload + 4 > payload_end) { goto reject; }
      tls_ext_0.type = ntohs((uint16_t)(load_half(payload, 0)));
   DEBUG_MSG("tls_ext_0.type = %#04x\n", tls_ext_0.type);
      tls_ext_0.length = ntohs((uint16_t)(load_half(payload, 2)));
   DEBUG_MSG("tls_ext_0.length = %#04x\n", tls_ext_0.length);
      payload += 4;
      switch (tls_ext_0.type) {
         case 0: goto parse_sni_check;
         default: goto parse_extensions_skip;
      }
      goto reject;
   }
   parse_extensions_skip: {
      extensions_len_parsed_0 = ((extensions_len_parsed_0) + (tls_ext_0.length)) + (4);
      payload += (uint32_t)(tls_ext_0.length);
      goto parse_extensions_check;
   }
   parse_sni_check: {
      sni_list_len_parsed_0 = 0;
      switch ((uint8_t)((tls_ext_0.length) > (2))) {
         case 1: goto parse_sni_list_;
         default: goto reject;
      }
      goto reject;
   }
   parse_sni_list_: {
      if (payload + 2 > payload_end) { goto reject; }
      sni_list_len_0 = ntohs((uint16_t)(load_half(payload, 0)));
      payload += 2;
      goto parse_sni_list_check;
   }
   parse_sni_list_check: {
      switch ((uint8_t)(((sni_list_len_parsed_0) + (3)) >= (sni_list_len_0))) {
         case 1: goto reject;
         default: goto parse_sni_list;
      }
      goto reject;
   }
   parse_sni_list: {
      if (payload + 3 > payload_end) { goto reject; }
      tls_sni_0.type = ((uint8_t)(load_byte(payload, 0)));
   DEBUG_MSG("tls_sni_0.type = %#02x\n", tls_sni_0.type);
      tls_sni_0.length = ntohs((uint16_t)(load_half(payload, 1)));
   DEBUG_MSG("tls_sni_0.length = %#04x\n", tls_sni_0.length);
      payload += 3;
      switch (tls_sni_0.type) {
         case 0: goto parse_sni_list_elem_check;
         default: goto parse_sni_list_skip;
      }
      goto reject;
   }
   parse_sni_list_skip: {
      payload += (uint32_t)(tls_sni_0.length);
      sni_list_len_parsed_0 = ((sni_list_len_parsed_0) + (tls_sni_0.length)) + (3);
      goto parse_sni_list_check;
   }
   parse_sni_list_elem_check: {
      switch ((uint8_t)((tls_sni_0.length) > (0))) {
         case 1: goto parse_sni;
         default: goto parse_sni_list_skip;
      }
      goto reject;
   }
   parse_sni: {
      if (payload + (uint32_t)(tls_sni_0.length) > payload_end) { goto reject; }
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].sni) - 1 && i_ < (uint32_t)(tls_sni_0.length); i_++) {
            ext[0].sni[i_] = payload[i_];
         }
         ext[0].sni[i_] = 0;
      }
      payload += (uint32_t)(tls_sni_0.length);
      goto accept;
   }
   flush: {
      return resultFlush;
   }
   accept: {
      return resultAccept;
   }
   reject: {
      return resultReject;
   }
   return resultReject;
}

int https_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len)
{
   if (https_ext == NULL) {
      https_ext = (struct https_extension_s *) malloc(sizeof(struct https_extension_s));
      memset(https_ext, 0, sizeof(struct https_extension_s));
   }

   int ret = parser_https_create(flow, payload, payload_len, https_ext);
   if (ret == resultAccept) {
      flow_add_extension(flow, https_ext, flow_ext_https);
      https_ext = NULL;
      return 0;
   } else if (ret == resultFlush) {
      flow_add_extension(flow, https_ext, flow_ext_https);
      https_ext = NULL;
      return FLOW_FLUSH;
   } else if (ret == resultExport) {
      return FLOW_EXPORT;
   }

   return 0;
}
int https_update(struct flowrec_s *flow, const uint8_t *payload, int payload_len)
{
   if (https_ext == NULL) {
      https_ext = (struct https_extension_s *) malloc(sizeof(struct https_extension_s));
      memset(https_ext, 0, sizeof(struct https_extension_s));
   }

   struct https_extension_s *ext = https_ext;
   int updateFlow = flow_get_extension(flow, (void **) &ext, flow_ext_https);

   int ret = parser_https_update(flow, payload, payload_len, ext);
   if (ret == resultAccept) {
      if (!updateFlow) {
         flow_add_extension(flow, ext, flow_ext_https);
         https_ext = NULL;
      }
      return 0;
   } else if (ret == resultFlush) {
      return FLOW_FLUSH;
   }

   return 0;
}

static struct ntp_extension_s *ntp_ext = NULL;

int parser_ntp_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len, struct ntp_extension_s *ext)
{ 
   const uint8_t *payload_end = payload + payload_len;
   (void) payload_end;
   goto start;
   goto accept;
   goto reject;
   start: {
      if (payload + 48 > payload_end) { goto reject; }
      ext[0].li = (uint8_t)((load_byte(payload, 0)) >> 6) & FPP_MASK(uint8_t, 2);
   DEBUG_MSG("ext[0].li = %#02x\n", ext[0].li);
      ext[0].vn = (uint8_t)((load_byte(payload, 0)) >> 3) & FPP_MASK(uint8_t, 3);
   DEBUG_MSG("ext[0].vn = %#02x\n", ext[0].vn);
      ext[0].mode = ((uint8_t)(load_byte(payload, 0))) & FPP_MASK(uint8_t, 3);
   DEBUG_MSG("ext[0].mode = %#02x\n", ext[0].mode);
      ext[0].stratum = ((uint8_t)(load_byte(payload, 1)));
   DEBUG_MSG("ext[0].stratum = %#02x\n", ext[0].stratum);
      ext[0].poll = ((uint8_t)(load_byte(payload, 2)));
   DEBUG_MSG("ext[0].poll = %#02x\n", ext[0].poll);
      ext[0].precision = ((uint8_t)(load_byte(payload, 3)));
   DEBUG_MSG("ext[0].precision = %#02x\n", ext[0].precision);
      ext[0].root_delay = ntohl((uint32_t)(load_word(payload, 4)));
   DEBUG_MSG("ext[0].root_delay = %#08x\n", ext[0].root_delay);
      ext[0].root_dispersion = ntohl((uint32_t)(load_word(payload, 8)));
   DEBUG_MSG("ext[0].root_dispersion = %#08x\n", ext[0].root_dispersion);
      ext[0].reference_id = ntohl((uint32_t)(load_word(payload, 12)));
   DEBUG_MSG("ext[0].reference_id = %#08x\n", ext[0].reference_id);
      ext[0].reference_ts = ntohll((uint64_t)(load_dword(payload, 16)));
   DEBUG_MSG("ext[0].reference_ts = %#016lx\n", ext[0].reference_ts);
      ext[0].origin_ts = ntohll((uint64_t)(load_dword(payload, 24)));
   DEBUG_MSG("ext[0].origin_ts = %#016lx\n", ext[0].origin_ts);
      ext[0].receive_ts = ntohll((uint64_t)(load_dword(payload, 32)));
   DEBUG_MSG("ext[0].receive_ts = %#016lx\n", ext[0].receive_ts);
      ext[0].transmit_ts = ntohll((uint64_t)(load_dword(payload, 40)));
   DEBUG_MSG("ext[0].transmit_ts = %#016lx\n", ext[0].transmit_ts);
      payload += 48;
      switch (ext[0].vn) {
         case 4: goto parse_ntp_check_mode;
         default: goto reject;
      }
      goto reject;
   }
   parse_ntp_check_mode: {
      switch (ext[0].mode) {
         case 3: goto parse_ntp_check_stratum;
         case 4: goto parse_ntp_check_stratum;
         default: goto reject;
      }
      goto reject;
   }
   parse_ntp_check_stratum: {
      switch ((uint8_t)((ext[0].stratum) > (16))) {
         case 1: goto reject;
         case 0: goto parse_ntp_check_poll;
      }
      goto reject;
   }
   parse_ntp_check_poll: {
      switch ((uint8_t)((ext[0].stratum) > (17))) {
         case 1: goto reject;
         case 0: goto flush;
      }
      goto reject;
   }
   flush: {
      return resultFlush;
   }
   accept: {
      return resultAccept;
   }
   reject: {
      return resultReject;
   }
   return resultReject;
}
int parser_ntp_update(struct flowrec_s *flow, const uint8_t *payload, int payload_len, struct ntp_extension_s *ext)
{ 
   const uint8_t *payload_end = payload + payload_len;
   (void) payload_end;
   goto start;
   goto accept;
   goto reject;
   start: {
      if (payload + 48 > payload_end) { goto reject; }
      ext[0].li = (uint8_t)((load_byte(payload, 0)) >> 6) & FPP_MASK(uint8_t, 2);
   DEBUG_MSG("ext[0].li = %#02x\n", ext[0].li);
      ext[0].vn = (uint8_t)((load_byte(payload, 0)) >> 3) & FPP_MASK(uint8_t, 3);
   DEBUG_MSG("ext[0].vn = %#02x\n", ext[0].vn);
      ext[0].mode = ((uint8_t)(load_byte(payload, 0))) & FPP_MASK(uint8_t, 3);
   DEBUG_MSG("ext[0].mode = %#02x\n", ext[0].mode);
      ext[0].stratum = ((uint8_t)(load_byte(payload, 1)));
   DEBUG_MSG("ext[0].stratum = %#02x\n", ext[0].stratum);
      ext[0].poll = ((uint8_t)(load_byte(payload, 2)));
   DEBUG_MSG("ext[0].poll = %#02x\n", ext[0].poll);
      ext[0].precision = ((uint8_t)(load_byte(payload, 3)));
   DEBUG_MSG("ext[0].precision = %#02x\n", ext[0].precision);
      ext[0].root_delay = ntohl((uint32_t)(load_word(payload, 4)));
   DEBUG_MSG("ext[0].root_delay = %#08x\n", ext[0].root_delay);
      ext[0].root_dispersion = ntohl((uint32_t)(load_word(payload, 8)));
   DEBUG_MSG("ext[0].root_dispersion = %#08x\n", ext[0].root_dispersion);
      ext[0].reference_id = ntohl((uint32_t)(load_word(payload, 12)));
   DEBUG_MSG("ext[0].reference_id = %#08x\n", ext[0].reference_id);
      ext[0].reference_ts = ntohll((uint64_t)(load_dword(payload, 16)));
   DEBUG_MSG("ext[0].reference_ts = %#016lx\n", ext[0].reference_ts);
      ext[0].origin_ts = ntohll((uint64_t)(load_dword(payload, 24)));
   DEBUG_MSG("ext[0].origin_ts = %#016lx\n", ext[0].origin_ts);
      ext[0].receive_ts = ntohll((uint64_t)(load_dword(payload, 32)));
   DEBUG_MSG("ext[0].receive_ts = %#016lx\n", ext[0].receive_ts);
      ext[0].transmit_ts = ntohll((uint64_t)(load_dword(payload, 40)));
   DEBUG_MSG("ext[0].transmit_ts = %#016lx\n", ext[0].transmit_ts);
      payload += 48;
      switch (ext[0].vn) {
         case 4: goto parse_ntp_check_mode;
         default: goto reject;
      }
      goto reject;
   }
   parse_ntp_check_mode: {
      switch (ext[0].mode) {
         case 3: goto parse_ntp_check_stratum;
         case 4: goto parse_ntp_check_stratum;
         default: goto reject;
      }
      goto reject;
   }
   parse_ntp_check_stratum: {
      switch ((uint8_t)((ext[0].stratum) > (16))) {
         case 1: goto reject;
         case 0: goto parse_ntp_check_poll;
      }
      goto reject;
   }
   parse_ntp_check_poll: {
      switch ((uint8_t)((ext[0].stratum) > (17))) {
         case 1: goto reject;
         case 0: goto flush;
      }
      goto reject;
   }
   flush: {
      return resultFlush;
   }
   accept: {
      return resultAccept;
   }
   reject: {
      return resultReject;
   }
   return resultReject;
}

int ntp_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len)
{
   if (ntp_ext == NULL) {
      ntp_ext = (struct ntp_extension_s *) malloc(sizeof(struct ntp_extension_s));
      memset(ntp_ext, 0, sizeof(struct ntp_extension_s));
   }

   int ret = parser_ntp_create(flow, payload, payload_len, ntp_ext);
   if (ret == resultAccept) {
      flow_add_extension(flow, ntp_ext, flow_ext_ntp);
      ntp_ext = NULL;
      return 0;
   } else if (ret == resultFlush) {
      flow_add_extension(flow, ntp_ext, flow_ext_ntp);
      ntp_ext = NULL;
      return FLOW_FLUSH;
   } else if (ret == resultExport) {
      return FLOW_EXPORT;
   }

   return 0;
}
int ntp_update(struct flowrec_s *flow, const uint8_t *payload, int payload_len)
{
   if (ntp_ext == NULL) {
      ntp_ext = (struct ntp_extension_s *) malloc(sizeof(struct ntp_extension_s));
      memset(ntp_ext, 0, sizeof(struct ntp_extension_s));
   }

   struct ntp_extension_s *ext = ntp_ext;
   int updateFlow = flow_get_extension(flow, (void **) &ext, flow_ext_ntp);

   int ret = parser_ntp_update(flow, payload, payload_len, ext);
   if (ret == resultAccept) {
      if (!updateFlow) {
         flow_add_extension(flow, ext, flow_ext_ntp);
         ntp_ext = NULL;
      }
      return 0;
   } else if (ret == resultFlush) {
      return FLOW_FLUSH;
   }

   return 0;
}

static struct sip_extension_s *sip_ext = NULL;

int parser_sip_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len, struct sip_extension_s *ext)
{ 
   const uint8_t *payload_end = payload + payload_len;
   (void) payload_end;
   uint8_t key_1[512];
   key_1[0] = 0;
   uint8_t val_1[512];
   val_1[0] = 0;
   uint8_t method_1[10];
   method_1[0] = 0;
   uint8_t uri_1[128];
   uri_1[0] = 0;
   uint8_t resp_code_1[10];
   resp_code_1[0] = 0;
   uint8_t tmp_63;
   uint8_t tmp_64;
   uint8_t tmp_65;
   uint8_t tmp_66;
   uint8_t tmp_67;
   uint8_t tmp_68;
   uint8_t tmp_69;
   uint8_t tmp_70;
   uint8_t tmp_71;
   uint8_t tmp_72;
   uint8_t tmp_73;
   uint8_t tmp_74;
   uint8_t tmp_75;
   uint8_t tmp_76;
   uint8_t tmp_77;
   uint8_t tmp_78;
   uint8_t tmp_79;
   uint8_t tmp_80;
   uint8_t tmp_81;
   uint8_t tmp_82;
   goto start;
   goto accept;
   goto reject;
   start: {
      tmp_63 = regex_sip_6040635941264429671(payload, payload_end, &payload, method_1, sizeof(method_1), uri_1, sizeof(uri_1));
      switch ((uint8_t)(tmp_63)) {
         case 1: goto parse_header_request_check;
         case 0: goto parse_header_response;
      }
      goto reject;
   }
   parse_header_request_check: {
      switch (ext[0].msg_type) {
         case 0: goto parse_header_request_;
         default: goto flush;
      }
      goto reject;
   }
   parse_header_request_: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].request_uri) - 1 && uri_1[i_]; i_++) {
            ext[0].request_uri[i_] = uri_1[i_];
         }
         ext[0].request_uri[i_] = 0;
      }
      ext[0].msg_type = 1;
      tmp_64 = regex_sip_5462306868045633682(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_64)) {
         case 1: goto parse_fields;
         default: goto check_ack;
      }
      goto reject;
   }
   parse_header_response: {
      tmp_65 = regex_sip_7275063398945298902(payload, payload_end, &payload, resp_code_1, sizeof(resp_code_1));
      switch ((uint8_t)(tmp_65)) {
         case 1: goto parse_header_response_check;
         case 0: goto reject;
      }
      goto reject;
   }
   parse_header_response_check: {
      switch (ext[0].msg_type) {
         case 0: goto parse_header_response_;
         default: goto flush;
      }
      goto reject;
   }
   parse_header_response_: {
      ext[0].status_code = strtoull((const char *) resp_code_1, NULL, 0);
      ext[0].msg_type = 99;
      goto parse_fields;
   }
   check_ack: {
      ext[0].msg_type = 2;
      tmp_66 = regex_sip_16956443701230746937(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_66)) {
         case 1: goto parse_fields;
         default: goto check_cancel;
      }
      goto reject;
   }
   check_cancel: {
      ext[0].msg_type = 3;
      tmp_67 = regex_sip_18288776361479925058(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_67)) {
         case 1: goto parse_fields;
         default: goto check_bye;
      }
      goto reject;
   }
   check_bye: {
      ext[0].msg_type = 4;
      tmp_68 = regex_sip_4058077162105378156(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_68)) {
         case 1: goto parse_fields;
         default: goto check_register;
      }
      goto reject;
   }
   check_register: {
      ext[0].msg_type = 5;
      tmp_69 = regex_sip_18405895296614751714(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_69)) {
         case 1: goto parse_fields;
         default: goto check_options;
      }
      goto reject;
   }
   check_options: {
      ext[0].msg_type = 6;
      tmp_70 = regex_sip_12695820213868661575(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_70)) {
         case 1: goto parse_fields;
         default: goto check_publish;
      }
      goto reject;
   }
   check_publish: {
      ext[0].msg_type = 7;
      tmp_71 = regex_sip_16250651687722877417(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_71)) {
         case 1: goto parse_fields;
         default: goto check_notify;
      }
      goto reject;
   }
   check_notify: {
      ext[0].msg_type = 8;
      tmp_72 = regex_sip_12108815196634125945(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_72)) {
         case 1: goto parse_fields;
         default: goto check_info;
      }
      goto reject;
   }
   check_info: {
      ext[0].msg_type = 9;
      tmp_73 = regex_sip_958566060438879421(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_73)) {
         case 1: goto parse_fields;
         default: goto check_subscribe;
      }
      goto reject;
   }
   check_subscribe: {
      ext[0].msg_type = 10;
      tmp_74 = regex_sip_2244092928934076851(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_74)) {
         case 1: goto parse_fields;
         default: goto check_status;
      }
      goto reject;
   }
   check_status: {
      ext[0].msg_type = 99;
      tmp_75 = regex_sip_1352173392757520904(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_75)) {
         case 1: goto parse_fields;
         default: goto reject;
      }
      goto reject;
   }
   parse_fields: {
      tmp_76 = regex_sip_9954629388999303388(payload, payload_end, &payload, key_1, sizeof(key_1), val_1, sizeof(val_1));
      switch ((uint8_t)(tmp_76)) {
         case 1: goto check_from;
         case 0: goto accept;
      }
      goto reject;
   }
   check_from: {
      tmp_77 = regex_sip_4274360113148428379(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_77)) {
         case 1: goto parse_from;
         default: goto check_to;
      }
      goto reject;
   }
   parse_from: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].calling_party) - 1 && val_1[i_]; i_++) {
            ext[0].calling_party[i_] = val_1[i_];
         }
         ext[0].calling_party[i_] = 0;
      }
      goto parse_fields;
   }
   check_to: {
      tmp_78 = regex_sip_14966057433110365877(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_78)) {
         case 1: goto parse_to;
         default: goto check_via;
      }
      goto reject;
   }
   parse_to: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].called_party) - 1 && val_1[i_]; i_++) {
            ext[0].called_party[i_] = val_1[i_];
         }
         ext[0].called_party[i_] = 0;
      }
      goto parse_fields;
   }
   check_via: {
      tmp_79 = regex_sip_5344484862863782926(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_79)) {
         case 1: goto parse_via;
         default: goto check_callid;
      }
      goto reject;
   }
   parse_via: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].via) - 1 && val_1[i_]; i_++) {
            ext[0].via[i_] = val_1[i_];
         }
         ext[0].via[i_] = 0;
      }
      goto parse_fields;
   }
   check_callid: {
      tmp_80 = regex_sip_5750864030914592696(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_80)) {
         case 1: goto parse_callid;
         default: goto check_useragent;
      }
      goto reject;
   }
   parse_callid: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].call_id) - 1 && val_1[i_]; i_++) {
            ext[0].call_id[i_] = val_1[i_];
         }
         ext[0].call_id[i_] = 0;
      }
      goto parse_fields;
   }
   check_useragent: {
      tmp_81 = regex_sip_5218521091908217587(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_81)) {
         case 1: goto parse_useragent;
         default: goto check_cseq;
      }
      goto reject;
   }
   parse_useragent: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].user_agent) - 1 && val_1[i_]; i_++) {
            ext[0].user_agent[i_] = val_1[i_];
         }
         ext[0].user_agent[i_] = 0;
      }
      goto parse_fields;
   }
   check_cseq: {
      tmp_82 = regex_sip_14612721195332388417(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_82)) {
         case 1: goto parse_cseq;
         default: goto parse_fields;
      }
      goto reject;
   }
   parse_cseq: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].cseq) - 1 && val_1[i_]; i_++) {
            ext[0].cseq[i_] = val_1[i_];
         }
         ext[0].cseq[i_] = 0;
      }
      goto parse_fields;
   }
   flush: {
      return resultFlush;
   }
   accept: {
      return resultAccept;
   }
   reject: {
      return resultReject;
   }
   return resultReject;
}
int parser_sip_update(struct flowrec_s *flow, const uint8_t *payload, int payload_len, struct sip_extension_s *ext)
{ 
   const uint8_t *payload_end = payload + payload_len;
   (void) payload_end;
   uint8_t key_1[512];
   key_1[0] = 0;
   uint8_t val_1[512];
   val_1[0] = 0;
   uint8_t method_1[10];
   method_1[0] = 0;
   uint8_t uri_1[128];
   uri_1[0] = 0;
   uint8_t resp_code_1[10];
   resp_code_1[0] = 0;
   uint8_t tmp_63;
   uint8_t tmp_64;
   uint8_t tmp_65;
   uint8_t tmp_66;
   uint8_t tmp_67;
   uint8_t tmp_68;
   uint8_t tmp_69;
   uint8_t tmp_70;
   uint8_t tmp_71;
   uint8_t tmp_72;
   uint8_t tmp_73;
   uint8_t tmp_74;
   uint8_t tmp_75;
   uint8_t tmp_76;
   uint8_t tmp_77;
   uint8_t tmp_78;
   uint8_t tmp_79;
   uint8_t tmp_80;
   uint8_t tmp_81;
   uint8_t tmp_82;
   goto start;
   goto accept;
   goto reject;
   start: {
      tmp_63 = regex_sip_6040635941264429671(payload, payload_end, &payload, method_1, sizeof(method_1), uri_1, sizeof(uri_1));
      switch ((uint8_t)(tmp_63)) {
         case 1: goto parse_header_request_check;
         case 0: goto parse_header_response;
      }
      goto reject;
   }
   parse_header_request_check: {
      switch (ext[0].msg_type) {
         case 0: goto parse_header_request_;
         default: goto flush;
      }
      goto reject;
   }
   parse_header_request_: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].request_uri) - 1 && uri_1[i_]; i_++) {
            ext[0].request_uri[i_] = uri_1[i_];
         }
         ext[0].request_uri[i_] = 0;
      }
      ext[0].msg_type = 1;
      tmp_64 = regex_sip_5462306868045633682(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_64)) {
         case 1: goto parse_fields;
         default: goto check_ack;
      }
      goto reject;
   }
   parse_header_response: {
      tmp_65 = regex_sip_7275063398945298902(payload, payload_end, &payload, resp_code_1, sizeof(resp_code_1));
      switch ((uint8_t)(tmp_65)) {
         case 1: goto parse_header_response_check;
         case 0: goto reject;
      }
      goto reject;
   }
   parse_header_response_check: {
      switch (ext[0].msg_type) {
         case 0: goto parse_header_response_;
         default: goto flush;
      }
      goto reject;
   }
   parse_header_response_: {
      ext[0].status_code = strtoull((const char *) resp_code_1, NULL, 0);
      ext[0].msg_type = 99;
      goto parse_fields;
   }
   check_ack: {
      ext[0].msg_type = 2;
      tmp_66 = regex_sip_16956443701230746937(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_66)) {
         case 1: goto parse_fields;
         default: goto check_cancel;
      }
      goto reject;
   }
   check_cancel: {
      ext[0].msg_type = 3;
      tmp_67 = regex_sip_18288776361479925058(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_67)) {
         case 1: goto parse_fields;
         default: goto check_bye;
      }
      goto reject;
   }
   check_bye: {
      ext[0].msg_type = 4;
      tmp_68 = regex_sip_4058077162105378156(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_68)) {
         case 1: goto parse_fields;
         default: goto check_register;
      }
      goto reject;
   }
   check_register: {
      ext[0].msg_type = 5;
      tmp_69 = regex_sip_18405895296614751714(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_69)) {
         case 1: goto parse_fields;
         default: goto check_options;
      }
      goto reject;
   }
   check_options: {
      ext[0].msg_type = 6;
      tmp_70 = regex_sip_12695820213868661575(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_70)) {
         case 1: goto parse_fields;
         default: goto check_publish;
      }
      goto reject;
   }
   check_publish: {
      ext[0].msg_type = 7;
      tmp_71 = regex_sip_16250651687722877417(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_71)) {
         case 1: goto parse_fields;
         default: goto check_notify;
      }
      goto reject;
   }
   check_notify: {
      ext[0].msg_type = 8;
      tmp_72 = regex_sip_12108815196634125945(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_72)) {
         case 1: goto parse_fields;
         default: goto check_info;
      }
      goto reject;
   }
   check_info: {
      ext[0].msg_type = 9;
      tmp_73 = regex_sip_958566060438879421(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_73)) {
         case 1: goto parse_fields;
         default: goto check_subscribe;
      }
      goto reject;
   }
   check_subscribe: {
      ext[0].msg_type = 10;
      tmp_74 = regex_sip_2244092928934076851(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_74)) {
         case 1: goto parse_fields;
         default: goto check_status;
      }
      goto reject;
   }
   check_status: {
      ext[0].msg_type = 99;
      tmp_75 = regex_sip_1352173392757520904(method_1, method_1 + sizeof(method_1), NULL);
      switch ((uint8_t)(tmp_75)) {
         case 1: goto parse_fields;
         default: goto reject;
      }
      goto reject;
   }
   parse_fields: {
      tmp_76 = regex_sip_9954629388999303388(payload, payload_end, &payload, key_1, sizeof(key_1), val_1, sizeof(val_1));
      switch ((uint8_t)(tmp_76)) {
         case 1: goto check_from;
         case 0: goto accept;
      }
      goto reject;
   }
   check_from: {
      tmp_77 = regex_sip_4274360113148428379(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_77)) {
         case 1: goto parse_from;
         default: goto check_to;
      }
      goto reject;
   }
   parse_from: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].calling_party) - 1 && val_1[i_]; i_++) {
            ext[0].calling_party[i_] = val_1[i_];
         }
         ext[0].calling_party[i_] = 0;
      }
      goto parse_fields;
   }
   check_to: {
      tmp_78 = regex_sip_14966057433110365877(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_78)) {
         case 1: goto parse_to;
         default: goto check_via;
      }
      goto reject;
   }
   parse_to: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].called_party) - 1 && val_1[i_]; i_++) {
            ext[0].called_party[i_] = val_1[i_];
         }
         ext[0].called_party[i_] = 0;
      }
      goto parse_fields;
   }
   check_via: {
      tmp_79 = regex_sip_5344484862863782926(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_79)) {
         case 1: goto parse_via;
         default: goto check_callid;
      }
      goto reject;
   }
   parse_via: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].via) - 1 && val_1[i_]; i_++) {
            ext[0].via[i_] = val_1[i_];
         }
         ext[0].via[i_] = 0;
      }
      goto parse_fields;
   }
   check_callid: {
      tmp_80 = regex_sip_5750864030914592696(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_80)) {
         case 1: goto parse_callid;
         default: goto check_useragent;
      }
      goto reject;
   }
   parse_callid: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].call_id) - 1 && val_1[i_]; i_++) {
            ext[0].call_id[i_] = val_1[i_];
         }
         ext[0].call_id[i_] = 0;
      }
      goto parse_fields;
   }
   check_useragent: {
      tmp_81 = regex_sip_5218521091908217587(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_81)) {
         case 1: goto parse_useragent;
         default: goto check_cseq;
      }
      goto reject;
   }
   parse_useragent: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].user_agent) - 1 && val_1[i_]; i_++) {
            ext[0].user_agent[i_] = val_1[i_];
         }
         ext[0].user_agent[i_] = 0;
      }
      goto parse_fields;
   }
   check_cseq: {
      tmp_82 = regex_sip_14612721195332388417(key_1, key_1 + sizeof(key_1), NULL);
      switch ((uint8_t)(tmp_82)) {
         case 1: goto parse_cseq;
         default: goto parse_fields;
      }
      goto reject;
   }
   parse_cseq: {
      {
         size_t i_;
         for (i_ = 0; i_ < sizeof(ext[0].cseq) - 1 && val_1[i_]; i_++) {
            ext[0].cseq[i_] = val_1[i_];
         }
         ext[0].cseq[i_] = 0;
      }
      goto parse_fields;
   }
   flush: {
      return resultFlush;
   }
   accept: {
      return resultAccept;
   }
   reject: {
      return resultReject;
   }
   return resultReject;
}

int sip_create(struct flowrec_s *flow, const uint8_t *payload, int payload_len)
{
   if (sip_ext == NULL) {
      sip_ext = (struct sip_extension_s *) malloc(sizeof(struct sip_extension_s));
      memset(sip_ext, 0, sizeof(struct sip_extension_s));
   }

   int ret = parser_sip_create(flow, payload, payload_len, sip_ext);
   if (ret == resultAccept) {
      flow_add_extension(flow, sip_ext, flow_ext_sip);
      sip_ext = NULL;
      return 0;
   } else if (ret == resultFlush) {
      flow_add_extension(flow, sip_ext, flow_ext_sip);
      sip_ext = NULL;
      return FLOW_FLUSH;
   } else if (ret == resultExport) {
      return FLOW_EXPORT;
   }

   return 0;
}
int sip_update(struct flowrec_s *flow, const uint8_t *payload, int payload_len)
{
   if (sip_ext == NULL) {
      sip_ext = (struct sip_extension_s *) malloc(sizeof(struct sip_extension_s));
      memset(sip_ext, 0, sizeof(struct sip_extension_s));
   }

   struct sip_extension_s *ext = sip_ext;
   int updateFlow = flow_get_extension(flow, (void **) &ext, flow_ext_sip);

   int ret = parser_sip_update(flow, payload, payload_len, ext);
   if (ret == resultAccept) {
      if (!updateFlow) {
         flow_add_extension(flow, ext, flow_ext_sip);
         sip_ext = NULL;
      }
      return 0;
   } else if (ret == resultFlush) {
      return FLOW_FLUSH;
   }

   return 0;
}


int check_plugins_string(const char *plugins)
{
   char tmp[sizeof(PLUGINS_AVAILABLE) + 1];
   char *token;
   uint8_t plugins_present[5] = { 0 };
   uint8_t basic_present = 0;
   size_t i;

   for (i = 0; i < sizeof(tmp) && plugins[i]; i++) {
      tmp[i] = plugins[i];
   }
   tmp[i] = 0;
   if (i >= sizeof(tmp) || i == 0) {
      return 0;
   }

   if (i > 0) {
      token = strtok(tmp, ",");
      while (token != NULL) {
         if (!strcmp(token, "basic") && !basic_present) {
            basic_present = 1;
         } else if (!strcmp(token, "http") && !plugins_present[flow_ext_http]) {
            plugins_present[flow_ext_http] = 1;
         } else if (!strcmp(token, "smtp") && !plugins_present[flow_ext_smtp]) {
            plugins_present[flow_ext_smtp] = 1;
         } else if (!strcmp(token, "https") && !plugins_present[flow_ext_https]) {
            plugins_present[flow_ext_https] = 1;
         } else if (!strcmp(token, "ntp") && !plugins_present[flow_ext_ntp]) {
            plugins_present[flow_ext_ntp] = 1;
         } else if (!strcmp(token, "sip") && !plugins_present[flow_ext_sip]) {
            plugins_present[flow_ext_sip] = 1;
         } else {
            return 0;
         }
         token = strtok(NULL, ",");
      }
   }

   return 1;
}

int add_plugins(struct flowcache_s *cache, const char *plugins)
{
   struct plugin_s *plugin;
   (void) plugin;
   if (cache->plugins == NULL) {
      cache->plugins = (struct plugin_s *) malloc(5 * sizeof(struct plugin_s));
      if (cache->plugins == NULL) {
         return 0;
      }
      cache->plugin_cnt = 0;
   } else {
      struct plugin_s *tmp = (struct plugin_s *) realloc(cache->plugins, (cache->plugin_cnt + 5) * sizeof(struct plugin_s));
      if (tmp == NULL) {
         return 0;
      }
      cache->plugins = tmp;
   }

   char tmp[sizeof(PLUGINS_AVAILABLE) + 1];
   char *token;
   size_t i;

   for (i = 0; i < sizeof(tmp) && plugins[i]; i++) {
      tmp[i] = plugins[i];
   }
   tmp[i] = 0;

   token = strtok(tmp, ",");
   while (token != NULL) { 
      if (!strcmp(token, "http")) {
         plugin = &cache->plugins[cache->plugin_cnt];
         plugin->name = "http";
         plugin->create = http_create;
         plugin->update = http_update;
         cache->plugin_cnt += 1;
      }
      if (!strcmp(token, "smtp")) {
         plugin = &cache->plugins[cache->plugin_cnt];
         plugin->name = "smtp";
         plugin->create = smtp_create;
         plugin->update = smtp_update;
         cache->plugin_cnt += 1;
      }
      if (!strcmp(token, "https")) {
         plugin = &cache->plugins[cache->plugin_cnt];
         plugin->name = "https";
         plugin->create = https_create;
         plugin->update = https_update;
         cache->plugin_cnt += 1;
      }
      if (!strcmp(token, "ntp")) {
         plugin = &cache->plugins[cache->plugin_cnt];
         plugin->name = "ntp";
         plugin->create = ntp_create;
         plugin->update = ntp_update;
         cache->plugin_cnt += 1;
      }
      if (!strcmp(token, "sip")) {
         plugin = &cache->plugins[cache->plugin_cnt];
         plugin->name = "sip";
         plugin->create = sip_create;
         plugin->update = sip_update;
         cache->plugin_cnt += 1;
      }
      token = strtok(NULL, ",");
   }

   return 1;
}

void finish_plugins()
{ 
   free(http_ext);
   free(smtp_ext);
   free(https_ext);
   free(ntp_ext);
   free(sip_ext);
}
