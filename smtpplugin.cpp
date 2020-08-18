/**
 * \file smtpplugin.cpp
 * \brief Plugin for parsing smtp traffic.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2018 CESNET
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
 * This software is provided as is'', and any express or implied
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

#include "smtpplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "ipfix-elements.h"

using namespace std;

#define SMTP_UNIREC_TEMPLATE "SMTP_2XX_STAT_CODE_COUNT,SMTP_3XX_STAT_CODE_COUNT,SMTP_4XX_STAT_CODE_COUNT,SMTP_5XX_STAT_CODE_COUNT,SMTP_COMMAND_FLAGS,SMTP_MAIL_CMD_COUNT,SMTP_RCPT_CMD_COUNT,SMTP_STAT_CODE_FLAGS,SMTP_DOMAIN,SMTP_FIRST_RECIPIENT,SMTP_FIRST_SENDER"

UR_FIELDS (
   uint32 SMTP_2XX_STAT_CODE_COUNT,
   uint32 SMTP_3XX_STAT_CODE_COUNT,
   uint32 SMTP_4XX_STAT_CODE_COUNT,
   uint32 SMTP_5XX_STAT_CODE_COUNT,
   uint32 SMTP_COMMAND_FLAGS,
   uint32 SMTP_MAIL_CMD_COUNT,
   uint32 SMTP_RCPT_CMD_COUNT,
   uint32 SMTP_STAT_CODE_FLAGS,
   string SMTP_DOMAIN,
   string SMTP_FIRST_SENDER,
   string SMTP_FIRST_RECIPIENT
)

SMTPPlugin::SMTPPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
   total = 0;
   replies_cnt = 0;
   commands_cnt = 0;
   ext_ptr = NULL;
}

SMTPPlugin::SMTPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   total = 0;
   replies_cnt = 0;
   commands_cnt = 0;
   ext_ptr = NULL;
}

const char *ipfix_smtp_template[] = {
   IPFIX_SMTP_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **SMTPPlugin::get_ipfix_string()
{
   return ipfix_smtp_template;
}

int SMTPPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (pkt.src_port == 25 || pkt.dst_port == 25) {
      create_smtp_record(rec, pkt);
   }

   return 0;
}

int SMTPPlugin::pre_update(Flow &rec, Packet &pkt)
{
   if (pkt.src_port == 25 || pkt.dst_port == 25) {
      RecordExt *ext = rec.getExtension(smtp);
      if (ext == NULL) {
         create_smtp_record(rec, pkt);
         return 0;
      }
      update_smtp_record(dynamic_cast<RecordExtSMTP *>(ext), pkt);
   }

   return 0;
}

/**
 * \brief Parse SMTP server data.
 *
 * \param [in] data Pointer to SMTP data.
 * \param [in] payload_len Length of `data` buffer.
 * \param [out] rec Pointer to SMTP extension record.
 * \return True on success, false otherwise.
 */
bool SMTPPlugin::parse_smtp_response(const char *data, int payload_len, RecordExtSMTP *rec)
{
   if (payload_len < 5 || !(data[3] == ' ' || data[3] == '-')) {
      return false;
   }
   for (int i = 0; i < 3; i++) {
      if (!isdigit(data[i])) {
         return false;
      }
   }

   switch (atoi(data)) {
      case 211:
         rec->mail_code_flags |= SMTP_SC_211;
         break;
      case 214:
         rec->mail_code_flags |= SMTP_SC_214;
         break;
      case 220:
         rec->mail_code_flags |= SMTP_SC_220;
         break;
      case 221:
         rec->mail_code_flags |= SMTP_SC_221;
         break;
      case 250:
         rec->mail_code_flags |= SMTP_SC_250;
         break;
      case 251:
         rec->mail_code_flags |= SMTP_SC_251;
         break;
      case 252:
         rec->mail_code_flags |= SMTP_SC_252;
         break;
      case 354:
         rec->mail_code_flags |= SMTP_SC_354;
         break;
      case 421:
         rec->mail_code_flags |= SMTP_SC_421;
         break;
      case 450:
         rec->mail_code_flags |= SMTP_SC_450;
         break;
      case 451:
         rec->mail_code_flags |= SMTP_SC_451;
         break;
      case 452:
         rec->mail_code_flags |= SMTP_SC_452;
         break;
      case 455:
         rec->mail_code_flags |= SMTP_SC_455;
         break;
      case 500:
         rec->mail_code_flags |= SMTP_SC_500;
         break;
      case 501:
         rec->mail_code_flags |= SMTP_SC_501;
         break;
      case 502:
         rec->mail_code_flags |= SMTP_SC_502;
         break;
      case 503:
         rec->mail_code_flags |= SMTP_SC_503;
         break;
      case 504:
         rec->mail_code_flags |= SMTP_SC_504;
         break;
      case 550:
         rec->mail_code_flags |= SMTP_SC_550;
         break;
      case 551:
         rec->mail_code_flags |= SMTP_SC_551;
         break;
      case 552:
         rec->mail_code_flags |= SMTP_SC_552;
         break;
      case 553:
         rec->mail_code_flags |= SMTP_SC_553;
         break;
      case 554:
         rec->mail_code_flags |= SMTP_SC_554;
         break;
      case 555:
         rec->mail_code_flags |= SMTP_SC_555;
         break;
      default:
         rec->mail_code_flags |= SC_UNKNOWN;
         break;
   }

   if (strcasestr(data, "SPAM") != NULL) {
      rec->mail_code_flags |= SC_SPAM;
   }

   switch (data[0]) {
      case '2':
         rec->code_2xx_cnt++;
         break;
      case '3':
         rec->code_3xx_cnt++;
         break;
      case '4':
         rec->code_4xx_cnt++;
         break;
      case '5':
         rec->code_5xx_cnt++;
         break;
      default:
         return false;
   }

   replies_cnt++;
   return true;
}

/**
 * \brief Check for keyword.
 *
 * \param [in] data Pointer to data.
 * \return True on success, false otherwise.
 */
bool SMTPPlugin::smtp_keyword(const char *data)
{
   for (int i = 0; data[i]; i++) {
      if (!isupper(data[i])) {
         return false;
      }
   }
   return true;
}

/**
 * \brief Parse SMTP client traffic.
 *
 * \param [in] data Pointer to SMTP data.
 * \param [in] payload_len Length of `data` buffer.
 * \param [out] rec Pointer to SMTP extension record.
 * \return True on success, false otherwise.
 */
bool SMTPPlugin::parse_smtp_command(const char *data, int payload_len, RecordExtSMTP *rec)
{
   const char *begin, *end;
   char buffer[32];
   size_t len;

   if (payload_len == 0) {
      return false;
   }

   if (rec->data_transfer) {
      if (payload_len != 3 || strcmp(data, ".\r\n")) {
         return false;
      }
      rec->data_transfer = 0;
      return true;
   }

   begin = data;
   end = strchr(begin, '\r');

   len = end - begin;
   if (end == NULL) {
      return false;
   }
   end = strchr(begin, ' ');
   if (end != NULL) {
      len = end - begin;
   }
   if (len >= sizeof(buffer)) {
      return false;
   }

   memcpy(buffer, begin, len);
   buffer[len] = 0;

   if (!strcmp(buffer, "HELO") || !strcmp(buffer, "EHLO")) {
      if (rec->domain[0] == 0) {
         begin = end;
         end = strchr(begin, '\r');
         if (end != NULL && begin != NULL) {
            begin++;
            len = end - begin;

            memcpy(rec->domain, begin, len);
            rec->domain[len] = 0;
         }
      }
      if (!strcmp(buffer, "HELO")) {
         rec->command_flags |= SMTP_CMD_HELO;
      } else {
         rec->command_flags |= SMTP_CMD_EHLO;
      }
   } else if (!strcmp(buffer, "RCPT")) {
      rec->mail_rcpt_cnt++;
      if (rec->first_recipient[0] == 0) {
         begin = strchr(end + 1, ':');
         end = strchr(end, '\r');
         if (end != NULL && begin != NULL) {
            begin++;
            len = end - begin;

            memcpy(rec->first_recipient, begin, len);
            rec->first_recipient[len] = 0;
         }
      }
      rec->command_flags |= SMTP_CMD_RCPT;
   } else if (!strcmp(buffer, "MAIL")) {
      rec->mail_cmd_cnt++;
      if (rec->first_sender[0] == 0) {
         begin = strchr(end + 1, ':');
         end = strchr(end, '\r');
         if (end != NULL && begin != NULL) {
            begin++;
            len = end - begin;

            memcpy(rec->first_sender, begin, len);
            rec->first_sender[len] = 0;
         }
      }
      rec->command_flags |= SMTP_CMD_MAIL;
   } else if (!strcmp(buffer, "DATA")) {
      rec->data_transfer = 1;
      rec->command_flags |= SMTP_CMD_DATA;
   } else if (!strcmp(buffer, "VRFY")) {
      rec->command_flags |= SMTP_CMD_VRFY;
   } else if (!strcmp(buffer, "EXPN")) {
      rec->command_flags |= SMTP_CMD_EXPN;
   } else if (!strcmp(buffer, "HELP")) {
      rec->command_flags |= SMTP_CMD_HELP;
   } else if (!strcmp(buffer, "NOOP")) {
      rec->command_flags |= SMTP_CMD_NOOP;
   } else if (!strcmp(buffer, "QUIT")) {
      rec->command_flags |= SMTP_CMD_QUIT;
   } else if (!smtp_keyword(buffer)) {
      rec->command_flags |= CMD_UNKNOWN;
   }

   commands_cnt++;
   return true;
}

void SMTPPlugin::create_smtp_record(Flow &rec, const Packet &pkt)
{
   if (ext_ptr == NULL) {
      ext_ptr = new RecordExtSMTP();
   }

   if (update_smtp_record(ext_ptr, pkt)) {
      rec.addExtension(ext_ptr);
      ext_ptr = NULL;
   }
}

bool SMTPPlugin::update_smtp_record(RecordExtSMTP *ext, const Packet &pkt)
{
   total++;
   if (pkt.src_port == 25) {
      return parse_smtp_response(pkt.payload, pkt.payload_length, ext);
   } else if (pkt.dst_port == 25) {
      return parse_smtp_command(pkt.payload, pkt.payload_length, ext);
   }

   return false;
}

void SMTPPlugin::finish()
{
   if (print_stats) {
      cout << "SMTP plugin stats:" << endl;
      cout << "   Total SMTP packets: " << total << endl;
      cout << "   Parsed SMTP replies: " << replies_cnt << endl;
      cout << "   Parsed SMTP commands: " << commands_cnt << endl;
   }
}

string SMTPPlugin::get_unirec_field_string()
{
   return SMTP_UNIREC_TEMPLATE;
}

bool SMTPPlugin::include_basic_flow_fields()
{
   return true;
}

