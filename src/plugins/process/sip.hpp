/**
 * \file sip.hpp
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

#ifndef IPXP_PROCESS_SIP_HPP
#define IPXP_PROCESS_SIP_HPP
#include <config.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

#ifdef WITH_NEMEA
#include <fields.h>
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/process.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define SIP_FIELD_LEN				128

#define SIP_MSG_TYPE_INVALID     0
#define SIP_MSG_TYPE_INVITE      1
#define SIP_MSG_TYPE_ACK         2
#define SIP_MSG_TYPE_CANCEL      3
#define SIP_MSG_TYPE_BYE         4
#define SIP_MSG_TYPE_REGISTER	   5
#define SIP_MSG_TYPE_OPTIONS	   6
#define SIP_MSG_TYPE_PUBLISH	   7
#define SIP_MSG_TYPE_NOTIFY      8
#define SIP_MSG_TYPE_INFO        9
#define SIP_MSG_TYPE_SUBSCRIBE   10
#define SIP_MSG_TYPE_STATUS      99

#define SIP_MSG_TYPE_TRYING         100
#define SIP_MSG_TYPE_DIAL_ESTABL	   101
#define SIP_MSG_TYPE_RINGING  	   180
#define SIP_MSG_TYPE_SESSION_PROGR  183
#define SIP_MSG_TYPE_OK	            200
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

/* Mininum length of SIP message: */
#define SIP_MIN_MSG_LEN     64

/*
 * SIP identification table - these are all patterns that must be contained
 * at the beginning of the SIP packet. They are folded in the same group if
 * they have same the letter on the same position.
 */
/* ** The first pattern test group: ** */
/*                                     v    */
#if BYTEORDER == 1234
#  define SIP_INVITE		0x49564e49	/* IVNI */
#else
#  define SIP_INVITE		0x494e5649	/* INVI */
#endif

#if BYTEORDER == 1234
#  define SIP_REGISTER		0x49474552	/* IGER */
#else
#  define SIP_REGISTER		0x52454749	/* REGI */
#endif

/*                                     vv   */
#if BYTEORDER == 1234
#  define SIP_NOTIFY		0x49544f4e	/* ITON */
#else
#  define SIP_NOTIFY		0x4e4f5449	/* NOTI */
#endif

#if BYTEORDER == 1234
#  define SIP_OPTIONS		0x4954504f	/* ITPO */
#else
#  define SIP_OPTIONS		0x4f505449	/* OPTI */
#endif

/*                                       v  */
#if BYTEORDER == 1234
#  define SIP_CANCEL		0x434e4143	/* CNAC */
#else
#  define SIP_CANCEL		0x43414e43	/* CANC */
#endif

/*                                        v */
#if BYTEORDER == 1234
#  define SIP_INFO		0x4f464e49	/* OFNI */
#else
#  define SIP_INFO		0x494e464f	/* INFO */
#endif

/* ** Test second pattern test group: ** */
/*                                     v    */
#if BYTEORDER == 1234
#  define SIP_ACK		0x204b4341	/*  KCA */
#else
#  define SIP_ACK		0x41434b20	/*  ACK */
#endif

#if BYTEORDER == 1234
#  define SIP_BYE		0x20455942	/*  EYB */
#else
#  define SIP_BYE		0x42594520	/*  BYE */
#endif

/*                                      v   */
#if BYTEORDER == 1234
#  define SIP_PUBLISH		0x4c425550	/* LBUP */
#else
#  define SIP_PUBLISH		0x5055424c	/* PUBL */
#endif

#if BYTEORDER == 1234
#  define SIP_SUBSCRIBE		0x53425553	/* SBUS */
#else
#  define SIP_SUBSCRIBE		0x53554253	/* SUBS */
#endif

/*                                       vv */
#if BYTEORDER == 1234
#  define SIP_REPLY	    	0x2f504953	/* /PIS */
#else
#  define SIP_REPLY	    	0x5349502f	/* SIP/ */
#endif

/* If one of the bytes in the tested packet equals to byte in the
 * test pattern, the packet *could* begin with the strings which
 * where used to make the test pattern.
 */
#if BYTEORDER == 1234
#  define SIP_TEST_1		0x49544149	/* ITAI */
#else
#  define SIP_TEST_1		0x49415449	/* IATI */
#endif

#if BYTEORDER == 1234
#define SIP_TEST_2		0x20424953	/*  BIS */
#else
#define SIP_TEST_2		0x53494220	/* SIB  */
#endif

/* MS SSDP notify header for detecting false SIP packets: */
#if BYTEORDER == 1234
#  define SIP_NOT_NOTIFY1	0x2a205946	/* * YF */
#else
#  define SIP_NOT_NOTIFY1	0x4659202a	/* FY * */
#endif

#if BYTEORDER == 1234
#  define SIP_NOT_NOTIFY2	0x54544820	/* TTH  */
#else
#  define SIP_NOT_NOTIFY2	0x20485454	/*  HTT */
#endif

#if BYTEORDER == 1234
#  define SIP_NOT_OPTIONS1	0x20534e4f	/*  SNO */
#else
#  define SIP_NOT_OPTIONS1	0x4f4e5320	/* ONS  */
#endif

#if BYTEORDER == 1234
#  define SIP_NOT_OPTIONS2	0x3a706973	/* :sip */
#else
#  define SIP_NOT_OPTIONS2	0x7369703a	/* pis: */
#endif

/*
 * SIP fields table - these patterns are used to quickly
 * detect necessary SIP fields.
 */
/* This macro converts low ASCII characters to upper case. Colon changes to 0x1a character: */
#if BYTEORDER == 1234
#  define SIP_UCFOUR(A)   ((A) & 0xdfdfdfdf)
#  define SIP_UCTWO(A)    ((A) & 0x0000dfdf)
#  define SIP_UCTHREE(A)  ((A) & 0x00dfdfdf)
#else
#  define SIP_UCFOUR(A)   ((A) & 0xdfdfdfdf)
#  define SIP_UCTWO(A)    ((A) & 0xdfdf0000)
#  define SIP_UCTHREE(A)  ((A) & 0xdfdfdf00)
#endif

/* Encoded SIP field names - long and short alternatives. The trailing number means the number of bytes to compare: */
#if BYTEORDER == 1234
#  define SIP_VIA4        0x1a414956	/* :AIV */
#else
#  define SIP_VIA4        0x5649411a	/* VIA: */
#endif

#if BYTEORDER == 1234
#  define SIP_VIA2        0x00001a56	/*   :V */
#else
#  define SIP_VIA2        0x561a0000	/* V:   */
#endif

#if BYTEORDER == 1234
#  define SIP_FROM4       0x4d4f5246	/* MORF */
#else
#  define SIP_FROM4       0x46524f4d	/* FROM */
#endif

#if BYTEORDER == 1234
#  define SIP_FROM2       0x00001a46	/*   :F */
#else
#  define SIP_FROM2       0x461a0000	/* F:   */
#endif

#if BYTEORDER == 1234
#  define SIP_TO3         0x001a4f54	/*  :OT */
#else
#  define SIP_TO3         0x544f1a00	/* TO:  */
#endif

#if BYTEORDER == 1234
#  define SIP_TO2         0x00001a54	/*   :T */
#else
#  define SIP_TO2         0x541a0000	/* T:   */
#endif

#if BYTEORDER == 1234
#  define SIP_CALLID4     0x4c4c4143	/* LLAC */
#else
#  define SIP_CALLID4     0x43414c4c	/* CALL */
#endif

#if BYTEORDER == 1234
#  define SIP_CALLID2     0x00001a49	/*   :I */
#else
#  define SIP_CALLID2     0x491a0000	/* I:   */
#endif

#if BYTEORDER == 1234
#  define SIP_CSEQ4       0x51455343	/* QESC */
#else
#  define SIP_CSEQ4       0x43534551	/* CSEQ */
#endif

#if BYTEORDER == 1234
#  define SIP_USERAGENT4  0x52455355	/* RESU */
#else
#  define SIP_USERAGENT4  0x55534552	/* USER */
#endif

/* Encoded SIP URI start: */
#if BYTEORDER == 1234
#  define SIP_URI         0x1a504953	/* :PIS */
#else
#  define SIP_URI         0x5349501a	/* SIP: */
#endif

#define SIP_URI_LEN     3
#if BYTEORDER == 1234
#  define SIP_URIS        0x1a535049	/* :SPI */
#else
#  define SIP_URIS        0x4950531a	/* IPS: */
#endif

#define SIP_URIS_LEN    4

/*
 * Bits 31, 24, 16, and 8 of this number are zero.  Call these bits
 * the "holes."  Note that there is a hole just to the left of
 * each byte, with an extra at the end:
 *
 * bits:  01111110 11111110 11111110 11111111
 * bytes: AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD
 *
 * The 1-bits make sure that carries propagate to the next 0-bit.
 * The 0-bits provide holes for carries to fall into.
 * The magic bits are added to the inspected part of string.
 * If the string contains zero byte, the corresponding hole
 * remains empty. Otherwise it is set to zero due of overflow.
 */

#ifdef __amd64__
#define MAGIC_INT       uint64_t
#define MAGIC_BITS      0x7efefefe7efefeffL
#define MAGIC_BITS_NEG  0x8101010181010100L
#else
#define MAGIC_INT       uint32_t
#define MAGIC_BITS      0x7efefeffL
#define MAGIC_BITS_NEG  0x81010100L
#endif

#define SIP_UNIREC_TEMPLATE  "SIP_MSG_TYPE,SIP_STATUS_CODE,SIP_CSEQ,SIP_CALLING_PARTY,SIP_CALLED_PARTY,SIP_CALL_ID,SIP_USER_AGENT,SIP_REQUEST_URI,SIP_VIA"

UR_FIELDS (
   uint16 SIP_MSG_TYPE,
   uint16 SIP_STATUS_CODE,
   string SIP_CSEQ,
   string SIP_CALLING_PARTY,
   string SIP_CALLED_PARTY,
   string SIP_CALL_ID,
   string SIP_USER_AGENT,
   string SIP_REQUEST_URI,
   string SIP_VIA
)

struct parser_strtok_t {
   parser_strtok_t()
   {
      separator_mask = 0;
      saveptr = nullptr;
      separator = 0;
      instrlen = 0;
   }

   MAGIC_INT separator_mask;
   const unsigned char *saveptr;
   char separator;
   unsigned int instrlen;
};

struct RecordExtSIP : public RecordExt {
   static int REGISTERED_ID;

   uint16_t msg_type;                  /* SIP message code (register, invite) < 100 or SIP response status > 100 */
   uint16_t status_code;
   char call_id[SIP_FIELD_LEN];	      /* Call id. For sevice SIP traffic call id = 0 */
   char calling_party[SIP_FIELD_LEN];	/* Calling party (ie. from) uri */
   char called_party[SIP_FIELD_LEN];	/* Called party (ie. to) uri */
   char via[SIP_FIELD_LEN];            /* Via field of SIP packet */
   char user_agent[SIP_FIELD_LEN];     /* User-Agent field of SIP packet */
   char cseq[SIP_FIELD_LEN];           /* CSeq field of SIP packet */
   char request_uri[SIP_FIELD_LEN];    /* Request-URI of SIP request */

   RecordExtSIP() : RecordExt(REGISTERED_ID)
   {
      msg_type = 0;
      status_code = 0;
      call_id[0] = 0;
      calling_party[0] = 0;
      called_party[0] = 0;
      via[0] = 0;
      user_agent[0] = 0;
      cseq[0] = 0;
      request_uri[0] = 0;
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_SIP_MSG_TYPE, msg_type);
      ur_set(tmplt, record, F_SIP_STATUS_CODE, status_code);
      ur_set_string(tmplt, record, F_SIP_CSEQ, cseq);
      ur_set_string(tmplt, record, F_SIP_CALLING_PARTY, calling_party);
      ur_set_string(tmplt, record, F_SIP_CALLED_PARTY, called_party);
      ur_set_string(tmplt, record, F_SIP_CALL_ID, call_id);
      ur_set_string(tmplt, record, F_SIP_USER_AGENT, user_agent);
      ur_set_string(tmplt, record, F_SIP_REQUEST_URI, request_uri);
      ur_set_string(tmplt, record, F_SIP_VIA, via);
   }

   const char *get_unirec_tmplt() const
   {
      return SIP_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      int length, total_length = 4;

      length = strlen(cseq);
      if (total_length + length + 1 > size) {
         return -1;
      }
      *(uint16_t *) (buffer) = ntohs(msg_type);
      *(uint16_t *) (buffer + 2) = ntohs(status_code);

      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, cseq, length);
      total_length += length + 1;

      length = strlen(calling_party);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, calling_party, length);
      total_length += length + 1;

      length = strlen(called_party);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, called_party, length);
      total_length += length + 1;

      length = strlen(call_id);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, call_id, length);
      total_length += length + 1;

      length = strlen(user_agent);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, user_agent, length);
      total_length += length + 1;

      length = strlen(request_uri);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, request_uri, length);
      total_length += length + 1;

      length = strlen(via);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, via, length);
      total_length += length + 1;

      return total_length;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_tmplt[] = {
         IPFIX_SIP_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };

      return ipfix_tmplt;
   }

   std::string get_text() const
   {
      std::ostringstream out;

      out << "sipmsgtype=" << msg_type
         << ",statuscode=" << status_code
         << ",cseq=\"" << cseq << "\""
         << ",callingparty=\"" << calling_party << "\""
         << ",calledparty=\"" << called_party << "\""
         << ",callid=\"" << call_id << "\""
         << ",useragent=\"" << user_agent << "\""
         << ",requri=\"" << request_uri << "\""
         << ",via=\"" << via << "\"";
      return out.str();
   }
};

class SIPPlugin : public ProcessPlugin {
public:
   SIPPlugin();
   ~SIPPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("sip", "Parse SIP traffic"); }
   std::string get_name() const { return "sip"; }
   RecordExt *get_ext() const { return new RecordExtSIP(); }
   ProcessPlugin *copy();
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish(bool print_stats);

private:
   uint16_t parse_msg_type(const Packet &pkt);
   const unsigned char *parser_strtok(const unsigned char *str, unsigned int instrlen, char separator, unsigned int *strlen, parser_strtok_t *nst);
   int parser_process_sip(const Packet &pkt, RecordExtSIP *sip_data);
   void parser_field_uri(const unsigned char *line, int linelen, int skip, char *dst, unsigned int dstlen);
   void parser_field_value(const unsigned char *line, int linelen, int skip, char *dst, unsigned int dstlen);

   uint32_t requests;
   uint32_t responses;
   uint32_t total;
   bool flow_flush;
};

}
#endif /* IPXP_PROCESS_SIP_HPP */
