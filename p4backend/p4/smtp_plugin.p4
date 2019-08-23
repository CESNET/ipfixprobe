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

#ifndef _SMTP_PLUGIN_P4_
#define _SMTP_PLUGIN_P4_

#include <core.p4>
#include "types.p4"
#include "plugin.p4"

/* Commands. */
#define SMTP_CMD_EHLO      0x0001
#define SMTP_CMD_HELO      0x0002
#define SMTP_CMD_MAIL      0x0004
#define SMTP_CMD_RCPT      0x0008
#define SMTP_CMD_DATA      0x0010
#define SMTP_CMD_RSET      0x0020
#define SMTP_CMD_VRFY      0x0040
#define SMTP_CMD_EXPN      0x0080
#define SMTP_CMD_HELP      0x0100
#define SMTP_CMD_NOOP      0x0200
#define SMTP_CMD_QUIT      0x0400
#define CMD_UNKNOWN        0x8000

/* Status codes. */
#define SMTP_SC_211        0x00000001
#define SMTP_SC_214        0x00000002
#define SMTP_SC_220        0x00000004
#define SMTP_SC_221        0x00000008
#define SMTP_SC_250        0x00000010
#define SMTP_SC_251        0x00000020
#define SMTP_SC_252        0x00000040
#define SMTP_SC_354        0x00000080
#define SMTP_SC_421        0x00000100
#define SMTP_SC_450        0x00000200
#define SMTP_SC_451        0x00000400
#define SMTP_SC_452        0x00000800
#define SMTP_SC_455        0x00001000
#define SMTP_SC_500        0x00002000
#define SMTP_SC_501        0x00004000
#define SMTP_SC_502        0x00008000
#define SMTP_SC_503        0x00010000
#define SMTP_SC_504        0x00020000
#define SMTP_SC_550        0x00040000
#define SMTP_SC_551        0x00080000
#define SMTP_SC_552        0x00100000
#define SMTP_SC_553        0x00200000
#define SMTP_SC_554        0x00400000
#define SMTP_SC_555        0x00800000
#define SC_SPAM            0x40000000 // indicates that answer contains SPAM keyword
#define SC_UNKNOWN         0x80000000

struct smtp_extension_s
{
   bit<32> code_2xx_cnt;
   bit<32> code_3xx_cnt;
   bit<32> code_4xx_cnt;
   bit<32> code_5xx_cnt;
   bit<32> command_flags;
   bit<32> mail_cmd_cnt;
   bit<32> mail_rcpt_cnt;
   bit<32> mail_code_flags;
   @stringbuf("255") bit<2040> domain; // 255 bytes
   @stringbuf("255") bit<2048> first_sender; // 255 bytes
   @stringbuf("255") bit<2048> first_recipient; // 255 bytes
   bit<8> data_transfer;
}

#define CODES(F) \
   F(211)\
   F(214)\
   F(220)\
   F(221)\
   F(250)\
   F(251)\
   F(252)\
   F(354)\
   F(421)\
   F(450)\
   F(451)\
   F(452)\
   F(455)\
   F(500)\
   F(501)\
   F(502)\
   F(503)\
   F(504)\
   F(550)\
   F(551)\
   F(552)\
   F(553)\
   F(554)\
   F(555)

#define GEN_TRANSITIONS(CODE) CODE: process_##CODE;

#define GEN_STATES(CODE) state process_##CODE {\
      ext.mail_code_flags = ext.mail_code_flags | SMTP_SC_##CODE;\
      transition check_response_2xx;\
   }

parser smtp_plugin_parser(payload p, in flowrec_s flow, out smtp_extension_s ext)
{
   @regex("\r\n")
   bit<1> end_of_header_fields;

   @regex("([A-Za-z]{4,})([ ]|\"\r\n\")")
   bit<1> re_command;

   @regex("([0-9]{3})([ -])")
   bit<1> re_response;

   @regex("\"\x00\"")
   bit<1> re_empty;

   @stringbuf("512") bit<1> key;
   @stringbuf("512") bit<1> val;

   @stringbuf ("9") bit<1> command;
   @stringbuf ("1") bit<1> dummy;
   @stringbuf ("4") bit<1> code;
   @stringbuf ("2") bit<1> delim;

   state start {
      transition check_sport;
   }
   state check_sport {
      transition select(flow.src_port) {
         25: check_data_transfer_;
         default: check_dport;
      }
   }
   state check_dport {
      transition select(flow.dst_port) {
         25: check_data_transfer_;
         default: reject;
      }
   }
   state check_data_transfer_ {
      transition select(ext.data_transfer) {
         1: check_data_transfer;
         default: parse_smtp_command;
      }
   }
   state check_data_transfer {
      @regex("\".\r\n\"") bit<1> re_end_of_data_transfer;
      transition select(p.lookahead_re(re_end_of_data_transfer)) {
         true: end_transfer;
         default: reject;
      }
   }
   state end_transfer {
      ext.data_transfer = 0;
      transition accept;
   }
   state parse_smtp_command {
      transition select (p.extract_re(re_command, {command, dummy})) {
         true: parse_smtp_command_;
         default: parse_smtp_response;
      }
   }
   state parse_smtp_response {
      transition select (p.extract_re(re_response, {code, delim})) {
         true: parse_smtp_response_;
         default: reject;
      }
   }
   state parse_smtp_command_ {
      transition check_helo;
   }
   state check_helo {
      @regex("'HELO\x00'") bit<1> re_helo;
      transition select(p.match(re_helo, command)) {
         true: process_helo;
         default: check_ehlo;
      }
   }
   state check_ehlo {
      @regex("'EHLO\x00'") bit<1> re_ehlo;
      transition select(p.match(re_ehlo, command)) {
         true: process_ehlo;
         default: check_rcpt;
      }
   }
   state process_helo {
      ext.command_flags = ext.command_flags | SMTP_CMD_HELO;
      transition select(p.match(re_empty, ext.domain)) {
         true: parse_domain;
         default: accept;
      }
   }
   state process_ehlo {
      ext.command_flags = ext.command_flags | SMTP_CMD_EHLO;
      transition select(p.match(re_empty, ext.domain)) {
         true: parse_domain;
         default: accept;
      }
   }
   state parse_domain {
      @regex("(.*)\"\r\n\"") bit<1> re_domain;
      transition select(p.extract_re(re_domain, ext.domain)) {
         default: accept;
      }
   }
   state check_rcpt {
      @regex("'RCPT\x00'") bit<1> re_rcpt;
      transition select(p.match(re_rcpt, command)) {
         true: process_rcpt;
         default: check_mail;
      }
   }
   state process_rcpt {
      ext.mail_rcpt_cnt = ext.mail_rcpt_cnt + 1;
      ext.command_flags = ext.command_flags | SMTP_CMD_RCPT;
      transition select(p.match(re_empty, ext.first_recipient)) {
         true: parse_rcpt;
         default: accept;
      }
   }
   state parse_rcpt {
      @regex("'TO: '(.*)\"\r\n\"") bit<1> re_rcpt;
      transition select(p.extract_re(re_rcpt, ext.first_recipient)) {
         default: accept;
      }
   }
   state check_mail {
      @regex("'MAIL\x00'") bit<1> re_mail;
      transition select(p.match(re_mail, command)) {
         true: process_mail;
         default: check_data;
      }
   }
   state process_mail {
      ext.mail_cmd_cnt = ext.mail_cmd_cnt + 1;
      ext.command_flags = ext.command_flags | SMTP_CMD_MAIL;
      transition select(p.match(re_empty, ext.first_sender)) {
         true: parse_mail;
         default: accept;
      }
   }
   state parse_mail {
      @regex("'FROM: '(.*)\"\r\n\"") bit<1> re_mail;
      transition select(p.extract_re(re_mail, ext.first_sender)) {
         default: accept;
      }
   }
   state check_data {
      @regex("'DATA\x00'") bit<1> re_data;
      transition select(p.match(re_data, command)) {
         true: process_data;
         default: check_vrfy;
      }
   }
   state process_data {
      ext.command_flags = ext.command_flags | SMTP_CMD_DATA;
      ext.data_transfer = 1;
      transition accept;
   }
   state check_vrfy {
      @regex("'VRFY\x00'") bit<1> re_vrfy;
      transition select(p.match(re_vrfy, command)) {
         true: process_vrfy;
         default: check_expn;
      }
   }
   state process_vrfy {
      ext.command_flags = ext.command_flags | SMTP_CMD_VRFY;
      transition accept;
   }
   state check_expn {
      @regex("'EXPN\x00'") bit<1> re_expn;
      transition select(p.match(re_expn, command)) {
         true: process_expn;
         default: check_help;
      }
   }
   state process_expn {
      ext.command_flags = ext.command_flags | SMTP_CMD_EXPN;
      transition accept;
   }
   state check_help {
      @regex("'HELP\x00'") bit<1> re_help;
      transition select(p.match(re_help, command)) {
         true: process_help;
         default: check_noop;
      }
   }
   state process_help {
      ext.command_flags = ext.command_flags | SMTP_CMD_HELP;
      transition accept;
   }
   state check_noop {
      @regex("'NOOP\x00'") bit<1> re_noop;
      transition select(p.match(re_noop, command)) {
         true: process_noop;
         default: check_quit;
      }
   }
   state process_noop {
      ext.command_flags = ext.command_flags | SMTP_CMD_NOOP;
      transition accept;
   }
   state check_quit {
      @regex("'QUIT\x00'") bit<1> re_quit;
      transition select(p.match(re_quit, command)) {
         true: process_quit;
         default: process_unknown_command;
      }
   }
   state process_quit {
      ext.command_flags = ext.command_flags | SMTP_CMD_QUIT;
      transition accept;
   }
   state process_unknown_command {
      ext.command_flags = ext.command_flags | CMD_UNKNOWN;
      transition accept;
   }

   state parse_smtp_response_ {
      bit<16> code_number;
      p.to_number(code, code_number);

      transition select(code_number) {
         CODES(GEN_TRANSITIONS)
         default: process_unknown_code;
      }
   }

   CODES(GEN_STATES)
   state process_unknown_code {
      ext.mail_code_flags = ext.mail_code_flags | SC_UNKNOWN;
      transition check_response_2xx;
   }

   state check_response_2xx {
      @regex("\"2\"") bit<1> re_2xx;
      transition select(p.match(re_2xx, code)) {
         true: process_response_2xx;
         default: check_response_3xx;
      }
   }
   state process_response_2xx {
      ext.code_2xx_cnt = ext.code_2xx_cnt + 1;
      transition check_spam;
   }
   state check_response_3xx {
      @regex("\"3\"") bit<1> re_3xx;
      transition select(p.match(re_3xx, code)) {
         true: process_response_3xx;
         default: check_response_4xx;
      }
   }
   state process_response_3xx {
      ext.code_3xx_cnt = ext.code_3xx_cnt + 1;
      transition check_spam;
   }
   state check_response_4xx {
      @regex("\"4\"") bit<1> re_4xx;
      transition select(p.match(re_4xx, code)) {
         true: process_response_4xx;
         default: check_response_5xx;
      }
   }
   state process_response_4xx {
      ext.code_4xx_cnt = ext.code_4xx_cnt + 1;
      transition check_spam;
   }
   state check_response_5xx {
      @regex("\"5\"") bit<1> re_5xx;
      transition select(p.match(re_5xx, code)) {
         true: process_response_5xx;
         default: check_spam;
      }
   }
   state process_response_5xx {
      ext.code_5xx_cnt = ext.code_5xx_cnt + 1;
      transition check_spam;
   }
   state check_spam {
      @regex(".*'SPAM'") bit<1> re_spam;
      transition select(p.lookahead_re(re_spam)) {
         true: process_spam;
         default: accept;
      }
   }
   state process_spam {
      ext.mail_code_flags = ext.mail_code_flags | SC_SPAM;
      transition accept;
   }
}

control smtp_plugin_export(in flowrec_s flow, in smtp_extension_s ext, ipfix_exporter e)
{
   apply {
      FILL_IPFIX_TEMPLATE(IPFIX_TEMPLATE_IPV4_SMTP, IPFIX_TEMPLATE_IPV6_SMTP);

      e.add_field(ext.command_flags); // commands
      e.add_field(ext.mail_cmd_cnt); // mail count
      e.add_field(ext.mail_rcpt_cnt); // rcpt count
      e.add_field(ext.mail_code_flags); // status codes
      e.add_field(ext.code_2xx_cnt); // 2xx count
      e.add_field(ext.code_3xx_cnt); // 3xx count
      e.add_field(ext.code_4xx_cnt); // 4xx count
      e.add_field(ext.code_5xx_cnt); // 5xx count
      e.add_field(ext.domain); // domain
      e.add_field(ext.first_sender); // sender
      e.add_field(ext.first_recipient); // recipients

      e.set_finish();
   }
}

#endif
