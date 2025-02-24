/**
 * \file sip.cpp
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2015-2016 CESNET
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

#include <iostream>
#include <cstdlib>
#include <cstring>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "sip.hpp"

namespace ipxp {

int RecordExtSIP::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("sip", [](){return new SIPPlugin();});
   register_plugin(&rec);
   RecordExtSIP::REGISTERED_ID = register_extension();
}

SIPPlugin::SIPPlugin() : requests(0), responses(0), total(0), flow_flush(false)
{
}

SIPPlugin::~SIPPlugin()
{
   close();
}

void SIPPlugin::init(const char *params)
{
}

void SIPPlugin::close()
{
}

ProcessPlugin *SIPPlugin::copy()
{
   return new SIPPlugin(*this);
}

int SIPPlugin::post_create(Flow &rec, const Packet &pkt)
{
   uint16_t msg_type;

   msg_type = parse_msg_type(pkt);
   if (msg_type == SIP_MSG_TYPE_INVALID) {
      return 0;
   }

   RecordExtSIP *sip_data = new RecordExtSIP();
   sip_data->msg_type = msg_type;
   rec.add_extension(sip_data);
   parser_process_sip(pkt, sip_data);

   return 0;
}

int SIPPlugin::pre_update(Flow &rec, Packet &pkt)
{
   uint16_t msg_type;

   msg_type = parse_msg_type(pkt);
   if (msg_type != SIP_MSG_TYPE_INVALID) {
      return FLOW_FLUSH_WITH_REINSERT;
   }

   return 0;
}

void SIPPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "SIP plugin stats:" << std::endl;
      std::cout << "   Parsed sip requests: " << requests << std::endl;
      std::cout << "   Parsed sip responses: " << responses << std::endl;
      std::cout << "   Total sip packets processed: " << total << std::endl;
   }
}

uint16_t SIPPlugin::parse_msg_type(const Packet &pkt)
{
   if (pkt.payload_len == 0) {
      return SIP_MSG_TYPE_INVALID;
   }

   uint32_t *first_bytes;
   uint32_t check;

   /* Is there any payload to process? */
   if (pkt.payload_len < SIP_MIN_MSG_LEN) {
      return SIP_MSG_TYPE_INVALID;
   }

   /* Get first four bytes of the packet and compare them against the patterns: */
   first_bytes = (uint32_t *) pkt.payload;

   /* Apply the pattern on the packet: */
   check = *first_bytes ^ SIP_TEST_1;

   /*
    * Here we will check if at least one of bytes in the SIP pattern is present in the packet.
    * Add magic_bits to longword
    *                |      Set those bits which were unchanged by the addition
    *                |             |        Look at the hole bits. If some of them is unchanged,
    *                |             |            |    most likely there is zero byte, ie. our separator.
    *                v             v            v                                                       */
   if ((((check + MAGIC_BITS) ^ ~check) & MAGIC_BITS_NEG) != 0) {
      /* At least one byte of the test pattern was found -> the packet *may* contain one of the searched SIP messages: */
      switch (*first_bytes) {
      case SIP_REGISTER:
         return SIP_MSG_TYPE_REGISTER;
      case SIP_INVITE:
         return SIP_MSG_TYPE_INVITE;
      case SIP_OPTIONS:
                /* OPTIONS message is also a request in HTTP - we must identify false positives here: */
         if (first_bytes[1] == SIP_NOT_OPTIONS1 && first_bytes[2] == SIP_NOT_OPTIONS2) {
            return SIP_MSG_TYPE_OPTIONS;
         }

         return SIP_MSG_TYPE_INVALID;
      case SIP_NOTIFY:	/* Notify message is a bit tricky because also Microsoft's SSDP protocol uses HTTP-like structure
                * and NOTIFY message - we must identify false positives here: */
         if (first_bytes[1] == SIP_NOT_NOTIFY1 && first_bytes[2] == SIP_NOT_NOTIFY2) {
            return SIP_MSG_TYPE_INVALID;
         }

         return SIP_MSG_TYPE_NOTIFY;
      case SIP_CANCEL:
         return SIP_MSG_TYPE_CANCEL;
      case SIP_INFO:
         return SIP_MSG_TYPE_INFO;
      default:
         break;
      }
   }

   /* Do the same thing for the second pattern: */
   check = *first_bytes ^ SIP_TEST_2;
   if ((((check + MAGIC_BITS) ^ ~check) & MAGIC_BITS_NEG) != 0) {
      switch (*first_bytes) {
      case SIP_REPLY:
         return SIP_MSG_TYPE_STATUS;
      case SIP_ACK:
         return SIP_MSG_TYPE_ACK;
      case SIP_BYE:
         return SIP_MSG_TYPE_BYE;
      case SIP_SUBSCRIBE:
         return SIP_MSG_TYPE_SUBSCRIBE;
      case SIP_PUBLISH:
         return SIP_MSG_TYPE_PUBLISH;
      default:
         break;
      }
   }

   /* No pattern found, this is probably not SIP packet: */
   return SIP_MSG_TYPE_INVALID;
}

const unsigned char * SIPPlugin::parser_strtok(const unsigned char *str, unsigned int instrlen, char separator, unsigned int *strlen, parser_strtok_t * nst)
{
   const unsigned char *char_ptr;	/* Currently processed characters */
   const unsigned char *beginning;	/* Beginning of the original string */
   MAGIC_INT *longword_ptr;	/* Currently processed word */
   MAGIC_INT longword;	/* Dereferenced longword_ptr useful for the next work */
   MAGIC_INT longword_mask;	/* Dereferenced longword_ptr with applied separator mask */
   const unsigned char *cp;	/* A byte which is supposed to be the next separator */
   int len;		/* Length of the string */
   MAGIC_INT i;

   /*
    * The idea of the algorithm comes from the implementation of stdlib function strlen().
    * See http://www.stdlib.net/~colmmacc/strlen.c.html for further details.
    */

   /* First or next run? */
   if (str != nullptr) {

      char_ptr = str;
      nst->saveptr = nullptr;
      nst->separator = separator;
      nst->instrlen = instrlen;

      /* Create a separator mask - put the separator to each byte of the integer: */
      nst->separator_mask = 0;
      for (i = 0; i < sizeof(longword) * 8; i += 8) {
         nst->separator_mask |= (((MAGIC_INT) separator) << i);
      }

   } else if (nst->saveptr != nullptr && nst->instrlen > 0) {
      /* Next run: */
      char_ptr = nst->saveptr;
   } else {
      /* Last run: */
      return nullptr;
   }

   /*
    * Handle the first few characters by reading one character at a time.
    * Do this until CHAR_PTR is aligned on a longword boundary:
    */
   len = 0;
   beginning = char_ptr;
   for (; ((unsigned long int)char_ptr & (sizeof(longword) - 1)) != 0; ++char_ptr) {

      /* We found the separator - return the string immediately: */
      if (*char_ptr == nst->separator) {
         *strlen = len;
         nst->saveptr = char_ptr + 1;
         if (nst->instrlen > 0) {
            nst->instrlen--;
         }
         return beginning;
      }
      len++;

      /* This is end of string - return the string as it is: */
      nst->instrlen--;
      if (nst->instrlen == 0) {
         *strlen = len;
         nst->saveptr = nullptr;
         return beginning;
      }
   }

#define FOUND(A)        { nst->saveptr = cp + (A) + 1; *strlen = len + A; nst->instrlen -= A + 1; return beginning; }

   /* Go across the string word by word: */
   longword_ptr = (MAGIC_INT *)char_ptr;
   for (;;) {
      /*
       * Get the current item and move to the next one. The XOR operator does the following thing:
       * If the byte is separator, sets it to zero. Otherwise it is nonzero.
       */
      longword = *longword_ptr++;
      longword_mask = longword ^ nst->separator_mask;

      /* Check the end of string. If we don't have enough bytes for the next longword, return what we have: */
      if (nst->instrlen < sizeof(longword)) {

         /* The separator could be just before the end of the buffer: */
         cp = (const unsigned char *)(longword_ptr - 1);
         for (i = 0; i < nst->instrlen; i++) {

            if (cp[i] == nst->separator) {
               /* Correct string length: */
               *strlen = len + i;

               /* If the separator is the last character in the buffer: */
               if (nst->instrlen == i + 1) {
                  nst->saveptr = nullptr;
               } else {
                  nst->saveptr = cp + i + 1;
                  nst->instrlen -= i + 1;
               }
               return beginning;
            }
         }
         /* Separator not found, so return the rest of buffer: */
         *strlen = len + nst->instrlen;
         nst->saveptr = nullptr;
         return beginning;
      }

      /*
       * Here we will try to find the separator:
       * Add magic_bits to longword
       *             |      Set those bits which were unchanged by the addition
       *             |             |        Look at the hole bits. If some of them is unchanged,
       *             |             |            |    most likely there is zero byte, ie. our separator.
       *             v             v            v                                                       */
      if ((((longword_mask + MAGIC_BITS) ^ ~longword_mask) & MAGIC_BITS_NEG) != 0) {

         /* Convert the integer back to the string: */
         cp = (const unsigned char *)(longword_ptr - 1);

         /* Find out which byte is the separator: */
         if (cp[0] == nst->separator)
            FOUND(0);
         if (cp[1] == nst->separator)
            FOUND(1);
         if (cp[2] == nst->separator)
            FOUND(2);
         if (cp[3] == nst->separator)
            FOUND(3);
         if (sizeof(longword) > 4) {
            if (cp[4] == nst->separator)
               FOUND(4);
            if (cp[5] == nst->separator)
               FOUND(5);
            if (cp[6] == nst->separator)
               FOUND(6);
            if (cp[7] == nst->separator)
               FOUND(7);
         }
      }

      /* Add the length: */
      len += sizeof(longword);
      nst->instrlen -= sizeof(longword);
   }
}

void SIPPlugin::parser_field_value(const unsigned char *line, int linelen, int skip, char *dst, unsigned int dstlen)
{
   parser_strtok_t pst;
   unsigned int newlen;

   /* Skip the leading characters: */
   line += skip;
   linelen -= skip;

   /* Skip whitespaces: */
   while (isalnum(*line) == 0 && linelen > 0) {
      line++;
      linelen--;
   }

   /* Trim trailing whitespaces: */
   while (isalnum(line[linelen - 1]) == 0 && linelen > 0) {
      linelen--;
   }

   /* Find the first field value: */
   line = parser_strtok(line, linelen, ';', &newlen, &pst);

   /* Trim to the length of the destination buffer: */
   if (newlen > dstlen - 1) {
      newlen = dstlen - 1;
   }

   /* Copy the buffer: */
   memcpy(dst, line, newlen);
   dst[newlen] = 0;
}

void SIPPlugin::parser_field_uri(const unsigned char *line, int linelen, int skip, char *dst, unsigned int dstlen)
{
   parser_strtok_t pst;
   unsigned int newlen;
   unsigned int final_len;
   uint32_t uri;
   const unsigned char *start;

   /* Skip leading characters: */
   line += skip;
   linelen -= skip;

   /* Find the first colon, this could be probably a part of the SIP uri: */
   start = nullptr;
   final_len = 0;
   line = parser_strtok(line, linelen, ':', &newlen, &pst);
   while (line != nullptr && newlen > 0) {
      /* Add the linelen to get the position of the first colon: */
      line += newlen;
      newlen = linelen - newlen;
      /* The characters before colon must be sip or sips: */
      uri = SIP_UCFOUR(*((uint32_t *) (line - SIP_URI_LEN)));
      if (uri == SIP_URI) {
         start = line - SIP_URI_LEN;
         final_len = newlen + SIP_URI_LEN;
         break;
      } else if (uri == SIP_URIS) {
         start = line - SIP_URIS_LEN;
         final_len = newlen + SIP_URIS_LEN;
         break;
      }

      /* Not a sip uri - find the next colon: */
      line = parser_strtok(nullptr, 0, ' ', &newlen, &pst);
   }

   /* No URI found? Exit: */
   if (start == nullptr) {
      return;
   }

   /* Now we have the beginning of the SIP uri. Find the end - >, ; or EOL: */
   line = parser_strtok(start, final_len, '>', &newlen, &pst);
   if (newlen < final_len) {
      final_len = newlen;
   } else {
      /* No bracket found, try to find at least a semicolon: */
      line = parser_strtok(start, final_len, ';', &newlen, &pst);
      if (newlen < final_len) {
         final_len = newlen;
      } else {
         /* Nor semicolon found. Strip the whitespaces from the end of line and use the whole line: */
         while (isalpha(start[final_len - 1]) == 0 && final_len > 0) {
            final_len--;
         }
      }
   }

   /* Trim to the length of the destination buffer: */
   if (final_len > dstlen - 1) {
      final_len = dstlen - 1;
   }

   /* Copy the buffer: */
   memcpy(dst, start, final_len);
   dst[final_len] = 0;
}

int SIPPlugin::parser_process_sip(const Packet &pkt, RecordExtSIP *sip_data)
{
   const unsigned char *payload;
   const unsigned char *line;
   int caplen;
   unsigned int line_len = 0;
   int field_len;
   parser_strtok_t line_parser;
   uint32_t first_bytes4;
   uint32_t first_bytes3;
   uint32_t first_bytes2;

   /* Skip the packet headers: */
   payload = (unsigned char *)pkt.payload;
   caplen = pkt.payload_len;

   /* Grab the first line of the payload: */
   line = parser_strtok(payload, caplen, '\n', &line_len, &line_parser);


   /* Get Request-URI for SIP requests from first line of the payload: */
   if (sip_data->msg_type <= 10) {
      requests++;
      /* Note: First SIP request line has syntax: "Method SP Request-URI SP SIP-Version CRLF" (SP=single space) */
      parser_strtok_t first_line_parser;
      const unsigned char *line_token;
      unsigned int line_token_len;

      /* Get Method part of request: */
      line_token = parser_strtok(line, line_len, ' ', &line_token_len, &first_line_parser);
      /* Get Request-URI part of request: */
      line_token = parser_strtok(nullptr, 0, ' ', &line_token_len, &first_line_parser);

      if (line_token != nullptr) {
         /* Request-URI: */
         parser_field_value(line_token, line_token_len, 0, sip_data->request_uri, sizeof(sip_data->request_uri));
      } else {
         /* Not found */
         sip_data->request_uri[0] = 0;
      }
   } else {
      responses++;
      if (sip_data->msg_type == 99) {
         parser_strtok_t first_line_parser;
         const unsigned char *line_token;
         unsigned int line_token_len;
         line_token = parser_strtok(line, line_len, ' ', &line_token_len, &first_line_parser);
         line_token = parser_strtok(nullptr, 0, ' ', &line_token_len, &first_line_parser);
         sip_data->status_code = SIP_MSG_TYPE_UNDEFINED;
         if (line_token) {
            sip_data->status_code = atoi((const char *)line_token);
         }
      }
   }

   total++;
   /* Go to the next line. Divide the packet payload by line breaks and process them one by one: */
   line = parser_strtok(nullptr, 0, ' ', &line_len, &line_parser);

   /*
    * Process all the remaining attributes:
    */
   while (line != nullptr && line_len > 1) {
      /* Get first 4, 3 and 2 bytes and compare them with searched SIP fields: */
      first_bytes4 = SIP_UCFOUR(*((uint32_t *) line));
      first_bytes3 = SIP_UCTHREE(*((uint32_t *) line));
      first_bytes2 = SIP_UCTWO(*((uint32_t *) line));

      /* From: */
      if (first_bytes4 == SIP_FROM4) {
         parser_field_uri(line, line_len, 5, sip_data->calling_party, sizeof(sip_data->calling_party));
      } else if (first_bytes2 == SIP_FROM2) {
         parser_field_uri(line, line_len, 2, sip_data->calling_party, sizeof(sip_data->calling_party));
      }

      /* To: */
      else if (first_bytes3 == SIP_TO3) {
         parser_field_uri(line, line_len, 3, sip_data->called_party, sizeof(sip_data->called_party));
      } else if (first_bytes2 == SIP_TO2) {
         parser_field_uri(line, line_len, 2, sip_data->called_party, sizeof(sip_data->called_party));
      }

      /* Via: */
      else if (first_bytes4 == SIP_VIA4) {
         /* Via fields can be present more times. Include all and separate them by semicolons: */
         if (sip_data->via[0] == 0) {
            parser_field_value(line, line_len, 4, sip_data->via, sizeof(sip_data->via));
         } else {
            field_len = strlen(sip_data->via);
            sip_data->via[field_len++] = ';';
            parser_field_value(line, line_len, 4, sip_data->via + field_len, sizeof(sip_data->via) - field_len);
         }
      } else if (first_bytes2 == SIP_VIA2) {
         if (sip_data->via[0] == 0) {
            parser_field_value(line, line_len, 2, sip_data->via, sizeof(sip_data->via));
         } else {
            field_len = strlen(sip_data->via);
            sip_data->via[field_len++] = ';';
            parser_field_value(line, line_len, 2, sip_data->via + field_len, sizeof(sip_data->via) - field_len);
         }
      }

      /* Call-ID: */
      else if (first_bytes4 == SIP_CALLID4) {
         parser_field_value(line, line_len, 8, sip_data->call_id, sizeof(sip_data->call_id));
      } else if (first_bytes2 == SIP_CALLID2) {
         parser_field_value(line, line_len, 2, sip_data->call_id, sizeof(sip_data->call_id));
      }

      /* User-Agent: */
      else if (first_bytes4 == SIP_USERAGENT4) {
         parser_field_value(line, line_len, 11, sip_data->user_agent, sizeof(sip_data->user_agent));
      }

      /* CSeq: */
      else if (first_bytes4 == SIP_CSEQ4) {

         /* Save CSeq: */
         parser_field_value(line, line_len, 5, sip_data->cseq, sizeof(sip_data->cseq));
      }

      /* Go to the next line: */
      line = parser_strtok(nullptr, 0, ' ', &line_len, &line_parser);
   }

   return 0;
}

}
