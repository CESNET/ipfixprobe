/**
 * \file smtp.hpp
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
 *
 *
 */

#ifndef IPXP_PROCESS_SMTP_HPP
#define IPXP_PROCESS_SMTP_HPP

#include <string>
#include <cstring>
#include <sstream>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

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

/**
 * \brief Flow record extension header for storing parsed SMTP packets.
 */
struct RecordExtSMTP : public RecordExt {
   static int REGISTERED_ID;

   uint32_t code_2xx_cnt;
   uint32_t code_3xx_cnt;
   uint32_t code_4xx_cnt;
   uint32_t code_5xx_cnt;
   uint32_t command_flags;
   uint32_t mail_cmd_cnt;
   uint32_t mail_rcpt_cnt;
   uint32_t mail_code_flags;
   char domain[255];
   char first_sender[255];
   char first_recipient[255];
   int data_transfer;

   /**
    * \brief Constructor.
    */
   RecordExtSMTP() : RecordExt(REGISTERED_ID)
   {
      code_2xx_cnt = 0;
      code_3xx_cnt = 0;
      code_4xx_cnt = 0;
      code_5xx_cnt = 0;
      command_flags = 0;
      mail_cmd_cnt = 0;
      mail_rcpt_cnt = 0;
      mail_code_flags = 0;
      domain[0] = 0;
      first_sender[0] = 0;
      first_recipient[0] = 0;
      data_transfer = 0;
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_SMTP_2XX_STAT_CODE_COUNT, code_2xx_cnt);
      ur_set(tmplt, record, F_SMTP_3XX_STAT_CODE_COUNT, code_3xx_cnt);
      ur_set(tmplt, record, F_SMTP_4XX_STAT_CODE_COUNT, code_4xx_cnt);
      ur_set(tmplt, record, F_SMTP_5XX_STAT_CODE_COUNT, code_5xx_cnt);
      ur_set(tmplt, record, F_SMTP_COMMAND_FLAGS, command_flags);
      ur_set(tmplt, record, F_SMTP_MAIL_CMD_COUNT, mail_cmd_cnt);
      ur_set(tmplt, record, F_SMTP_RCPT_CMD_COUNT, mail_rcpt_cnt);
      ur_set(tmplt, record, F_SMTP_STAT_CODE_FLAGS, mail_code_flags);
      ur_set_string(tmplt, record, F_SMTP_DOMAIN, domain);
      ur_set_string(tmplt, record, F_SMTP_FIRST_SENDER, first_sender);
      ur_set_string(tmplt, record, F_SMTP_FIRST_RECIPIENT, first_recipient);
   }

   const char *get_unirec_tmplt() const
   {
      return SMTP_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      int domain_len = strlen(domain);
      int sender_len = strlen(first_sender);
      int recipient_len = strlen(first_recipient);
      int length;

      if (domain_len + sender_len + recipient_len + 35 > size) {
         return -1;
      }

      *(uint32_t *) (buffer) = ntohl(command_flags);
      *(uint32_t *) (buffer + 4) = ntohl(mail_cmd_cnt);
      *(uint32_t *) (buffer + 8) = ntohl(mail_rcpt_cnt);
      *(uint32_t *) (buffer + 12) = ntohl(mail_code_flags);
      *(uint32_t *) (buffer + 16) = ntohl(code_2xx_cnt);
      *(uint32_t *) (buffer + 20) = ntohl(code_3xx_cnt);
      *(uint32_t *) (buffer + 24) = ntohl(code_4xx_cnt);
      *(uint32_t *) (buffer + 28) = ntohl(code_5xx_cnt);

      length = 32;
      buffer[length++] = domain_len;
      memcpy(buffer + length, domain, domain_len);

      length += domain_len;
      buffer[length++] = sender_len;
      memcpy(buffer + length, first_sender, sender_len);

      length += sender_len;
      buffer[length++] = recipient_len;
      memcpy(buffer + length, first_recipient, recipient_len);

      length += recipient_len;

      return length;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_SMTP_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };
      return ipfix_template;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "2xxcnt=" << code_2xx_cnt
         << ",3xxcnt=" << code_3xx_cnt
         << ",4xxcnt=" << code_4xx_cnt
         << ",5xxcnt=" << code_5xx_cnt
         << ",cmdflgs=" << command_flags
         << ",mailcmdcnt=" << mail_cmd_cnt
         << ",rcptcmdcnt=" << mail_rcpt_cnt
         << ",codeflags=" << mail_code_flags
         << ",domain=\"" << domain << "\""
         << ",firstsender=\"" << first_sender << "\""
         << ",firstrecipient=\"" << first_recipient << "\"";
      return out.str();
   }
};

/**
 * \brief Flow cache plugin for parsing SMTP packets.
 */
class SMTPPlugin : public ProcessPlugin
{
public:
   SMTPPlugin();
   ~SMTPPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("smtp", "Parse SMTP traffic"); }
   std::string get_name() const { return "smtp"; }
   RecordExt *get_ext() const { return new RecordExtSMTP(); }
   ProcessPlugin *copy();

   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish(bool print_stats);

   bool smtp_keyword(const char *data);
   bool parse_smtp_response(const char *data, int payload_len, RecordExtSMTP *rec);
   bool parse_smtp_command(const char *data, int payload_len, RecordExtSMTP *rec);
   void create_smtp_record(Flow &rec, const Packet &pkt);
   bool update_smtp_record(RecordExtSMTP *ext, const Packet &pkt);

private:
   RecordExtSMTP *ext_ptr; /**< Pointer to allocated record extension. */
   uint32_t total;         /**< Total number of SMTP packets seen. */
   uint32_t replies_cnt;   /**< Total number of SMTP replies. */
   uint32_t commands_cnt;  /**< Total number of SMTP commands. */
};

}
#endif /* IPXP_PROCESS_SMTP_HPP */
