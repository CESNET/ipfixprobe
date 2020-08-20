/**
 * \file dns.h
 * \brief DNS structs and macros.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2017 CESNET
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
 *
 */

#ifndef DNS_H
#define DNS_H

#include <stdint.h>

#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_PTR    12
#define DNS_TYPE_HINFO  13
#define DNS_TYPE_MINFO  14
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_ISDN   20
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_SRV    33
#define DNS_TYPE_DNAME  39
#define DNS_TYPE_DS     43
#define DNS_TYPE_RRSIG  46
#define DNS_TYPE_DNSKEY 48

#define DNS_TYPE_OPT    41

#define DNS_HDR_GET_QR(flags)       (((flags) & (0x1 << 15)) >> 15) // Return question/answer bit.
#define DNS_HDR_GET_OPCODE(flags)   (((flags) & (0xF << 11)) >> 11) // Return opcode bits.
#define DNS_HDR_GET_AA(flags)       (((flags) & (0x1 << 10)) >> 10) // Return authoritative answer bit.
#define DNS_HDR_GET_TC(flags)       (((flags) & (0x1 << 9)) >> 9) // Return truncation bit.
#define DNS_HDR_GET_RD(flags)       (((flags) & (0x1 << 8)) >> 8) // Return recursion desired bit.
#define DNS_HDR_GET_RA(flags)       (((flags) & (0x1 << 7)) >> 7) // Return recursion available bit.
#define DNS_HDR_GET_Z(flags)        (((flags) & (0x1 << 6)) >> 6) // Return reserved bit.
#define DNS_HDR_GET_AD(flags)       (((flags) & (0x1 << 5)) >> 5) // Return authentication data bit.
#define DNS_HDR_GET_CD(flags)       (((flags) & (0x1 << 4)) >> 4) // Return checking disabled bit.
#define DNS_HDR_GET_RESPCODE(flags) ((flags) & 0xF) // Return response code bits.

#define DNS_HDR_LENGTH 12

/**
 * \brief Struct containing DNS header fields.
 */
struct __attribute__ ((packed)) dns_hdr {
   uint16_t id;
   union {
      struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
         uint16_t recursion_desired:1;
         uint16_t truncation:1;
         uint16_t authoritative_answer:1;
         uint16_t op_code:4;
         uint16_t query_response:1;
         uint16_t response_code:4;
         uint16_t checking_disabled:1;
         uint16_t auth_data:1;
         uint16_t reserved:1;
         uint16_t recursion_available:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
         uint16_t query_response:1;
         uint16_t op_code:4;
         uint16_t authoritative_answer:1;
         uint16_t truncation:1;
         uint16_t recursion_desired:1;
         uint16_t recursion_available:1;
         uint16_t reserved:1;
         uint16_t auth_data:1;
         uint16_t checking_disabled:1;
         uint16_t response_code:4;
#endif
      };
      uint16_t flags;
   };
   uint16_t question_rec_cnt;
   uint16_t answer_rec_cnt;
   uint16_t name_server_rec_cnt;
   uint16_t additional_rec_cnt;
};

/**
 * \brief Struct containing DNS question.
 */
struct __attribute__ ((packed)) dns_question {
   /* name */
   uint16_t qtype;
   uint16_t qclass;
};

/**
 * \brief Struct containing DNS answer.
 */
struct __attribute__ ((packed)) dns_answer {
   /* name */
   uint16_t atype;
   uint16_t aclass;
   uint32_t ttl;
   uint16_t rdlength;
   /* rdata */
};

/**
 * \brief Struct containing DNS SOA record.
 */
struct __attribute__ ((packed)) dns_soa {
   /* primary NS */
   /* admin MB */
   uint32_t serial;
   uint32_t refresh;
   uint32_t retry;
   uint32_t expiration;
   uint32_t ttl;
};

/**
 * \brief Struct containing DNS SRV record.
 */
struct __attribute__ ((packed)) dns_srv {
   /* _service._proto.name*/
   uint16_t priority;
   uint16_t weight;
   uint16_t port;
   /* target */
};

/**
 * \brief Struct containing DNS DS record.
 */
struct __attribute__ ((packed)) dns_ds {
   uint16_t keytag;
   uint8_t algorithm;
   uint8_t digest_type;
   /* digest */
};

/**
 * \brief Struct containing DNS RRSIG record.
 */
struct __attribute__ ((packed)) dns_rrsig {
   uint16_t type;
   uint8_t algorithm;
   uint8_t labels;
   uint32_t ttl;
   uint32_t sig_expiration;
   uint32_t sig_inception;
   uint16_t keytag;
   /* signer's name */
   /* signature */
};

/**
 * \brief Struct containing DNS DNSKEY record.
 */
struct __attribute__ ((packed)) dns_dnskey {
   uint16_t flags;
   uint8_t protocol;
   uint8_t algorithm;
   /* public key */
};

#endif
