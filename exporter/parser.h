/**
 * \file parser.h
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

#ifndef P4E_GENERATED_PARSER
#define P4E_GENERATED_PARSER

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <endian.h>
#include <byteswap.h>

#include "types.h"

//#define DEBUG_PARSER

#ifdef DEBUG_PARSER
// Print debug message if debugging is allowed.
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

#define FPP_MASK(type, bits) (((type)(1) << (bits)) - (type)(1))
#define BYTES(w) ((w) / 8)
#define load_byte(ptr, bytes) (*(const uint8_t *)((const uint8_t *)(ptr) + bytes))
#define load_half(ptr, bytes) (*(const uint16_t *)((const uint8_t *)(ptr) + bytes))
#define load_word(ptr, bytes) (*(const uint32_t *)((const uint8_t *)(ptr) + bytes))
#define load_dword(ptr, bytes) (*(const uint64_t *)((const uint8_t *)(ptr) + bytes))

#if __BYTE_ORDER == __BIG_ENDIAN
#   define ntohll(x) __uint64_identity (x)
#else
#   if __BYTE_ORDER == __LITTLE_ENDIAN
#       define ntohll(x)  __bswap_64 (x)
#   endif
#endif

#ifndef PARSER_MAX_HEADER_COUNT
#define PARSER_MAX_HEADER_COUNT 5
#endif
#define PARSER_MAX_LINK_COUNT PARSER_MAX_HEADER_COUNT * 8

enum fpp_return_code { 
    ParserDefaultReject,
    OutOfMemory,
    NoError,
    PacketTooShort,
    NoMatch,
    StackOutOfBounds,
    HeaderTooShort,
    ParserTimeout,
    ParserInvalidArgument
};

enum fpp_header { 
    ethernet_h,
    ipv4_h,
    ipv6_h,
    tcp_h,
    udp_h,
    icmp_h,
    icmpv6_h,
    payload_h,
    noHeader
};

struct packet_hdr_s { 
    enum fpp_header type;
    void * data;
    uint32_t header_offset;
    struct packet_hdr_s * next;
};

struct fpp_parser_s { 
    struct ethernet_h eth[PARSER_MAX_HEADER_COUNT];
    struct ipv4_h ipv4[PARSER_MAX_HEADER_COUNT];
    struct ipv6_h ipv6[PARSER_MAX_HEADER_COUNT];
    struct tcp_h tcp[PARSER_MAX_HEADER_COUNT];
    struct udp_h udp[PARSER_MAX_HEADER_COUNT];
    struct icmp_h icmp[PARSER_MAX_HEADER_COUNT];
    struct icmpv6_h icmp6[PARSER_MAX_HEADER_COUNT];
    struct payload_h payload[PARSER_MAX_HEADER_COUNT];
    struct packet_hdr_s links[PARSER_MAX_LINK_COUNT];
    int link_count;
    int hdr_counts[8];
};

void fpp_init(struct fpp_parser_s *parser);
void fpp_free(struct fpp_parser_s *parser, struct packet_hdr_s *headers);
void fpp_clear(struct fpp_parser_s *parser);
enum fpp_return_code fpp_parse_packet(struct fpp_parser_s *parser, const uint8_t * packet_ptr, uint32_t packet_len, struct packet_hdr_s ** out);

#endif
