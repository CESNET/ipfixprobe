/**
 * \file smtp.cpp
 * \brief Plugin for parsing smtp traffic.
 * \author Jiri Havranek <havranek@cesnet.cz>
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
#include <cstring>
#include <ctype.h>

#include "common.hpp"
#include "smtp.hpp"

namespace ipxp {

int RecordExtSMTP::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("smtp", [](){return new SMTPPlugin();});
   register_plugin(&rec);
   RecordExtSMTP::REGISTERED_ID = register_extension();
}

SMTPPlugin::SMTPPlugin() : ext_ptr(nullptr), total(0), replies_cnt(0), commands_cnt(0)
{
}

SMTPPlugin::~SMTPPlugin()
{
   close();
}

void SMTPPlugin::init(const char *params)
{
}

void SMTPPlugin::close()
{
}

ProcessPlugin *SMTPPlugin::copy()
{
   return new SMTPPlugin(*this);
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
      RecordExt *ext = rec.get_extension(RecordExtSMTP::REGISTERED_ID);
      if (ext == nullptr) {
         create_smtp_record(rec, pkt);
         return 0;
      }
      update_smtp_record(static_cast<RecordExtSMTP *>(ext), pkt);
   }

   return 0;
}

char *strncasestr(const char *str, size_t n, const char *substr)
{
   size_t i = 0;
   size_t j = 0;
   while (i < n && *str) {
      if (tolower(*str) == tolower(substr[j])) {
         j++;
         if (!substr[j]) {
            return (char *) str;
         }
      } else {
         j = 0;
      }
      i++;
      str++;
   }
   return nullptr;
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

   if (strncasestr(data, payload_len, "SPAM") != nullptr) {
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
   size_t remaining;

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
   end = static_cast<const char *>(memchr(begin, '\r', payload_len));

   len = end - begin;
   if (end == nullptr) {
      return false;
   }
   end = static_cast<const char *>(memchr(begin, ' ', payload_len));
   if (end != nullptr) {
      len = end - begin;
   }
   if (len >= sizeof(buffer)) {
      return false;
   }

   memcpy(buffer, begin, len);
   buffer[len] = 0;

   if (!strcmp(buffer, "HELO") || !strcmp(buffer, "EHLO")) {
      if (rec->domain[0] == 0 && end != nullptr) {
         begin = end;
         remaining = payload_len - (begin - data);
         end = static_cast<const char *>(memchr(begin, '\r', remaining));
         if (end != nullptr && begin != NULL) {
            begin++;
            len = end - begin;
            if (len >= sizeof(rec->domain)) {
               len = sizeof(rec->domain) - 1;
            }

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
      if (rec->first_recipient[0] == 0 && end != nullptr) {
         if (check_payload_len(payload_len, (end + 1) - data)) {
            return false;
         }
         remaining = payload_len - ((end + 1) - data);
         begin = static_cast<const char *>(memchr(end + 1, ':', remaining));
         remaining = payload_len - (end - data);
         end = static_cast<const char *>(memchr(end, '\r', remaining));

         if (end != nullptr && begin != NULL) {
            begin++;
            len = end - begin;
            if (len >= sizeof(rec->first_recipient)) {
               len = sizeof(rec->first_recipient) - 1;
            }

            memcpy(rec->first_recipient, begin, len);
            rec->first_recipient[len] = 0;
         }
      }
      rec->command_flags |= SMTP_CMD_RCPT;
   } else if (!strcmp(buffer, "MAIL")) {
      rec->mail_cmd_cnt++;
      if (rec->first_sender[0] == 0 && end != nullptr) {
         if (check_payload_len(payload_len, (end + 1) - data)) {
            return false;
         }
         remaining = payload_len - ((end + 1) - data);
         begin = static_cast<const char *>(memchr(end + 1, ':', remaining));
         remaining = payload_len - (end - data);
         end = static_cast<const char *>(memchr(end, '\r', remaining));

         if (end != nullptr && begin != NULL) {
            begin++;
            len = end - begin;
            if (len >= sizeof(rec->first_sender)) {
               len = sizeof(rec->first_sender) - 1;
            }

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
   if (ext_ptr == nullptr) {
      ext_ptr = new RecordExtSMTP();
   }

   if (update_smtp_record(ext_ptr, pkt)) {
      rec.add_extension(ext_ptr);
      ext_ptr = nullptr;
   }
}

bool SMTPPlugin::update_smtp_record(RecordExtSMTP *ext, const Packet &pkt)
{
   total++;
   const char *payload = reinterpret_cast<const char *>(pkt.payload);
   if (pkt.src_port == 25) {
      return parse_smtp_response(payload, pkt.payload_len, ext);
   } else if (pkt.dst_port == 25) {
      return parse_smtp_command(payload, pkt.payload_len, ext);
   }

   return false;
}

void SMTPPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "SMTP plugin stats:" << std::endl;
      std::cout << "   Total SMTP packets: " << total << std::endl;
      std::cout << "   Parsed SMTP replies: " << replies_cnt << std::endl;
      std::cout << "   Parsed SMTP commands: " << commands_cnt << std::endl;
   }
}

}
