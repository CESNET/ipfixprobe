/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, CESNET z.s.p.o.
 */

/**
 * \file tls_parser.cpp
 * \brief Class for parsing TLS traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \date 2022
 */

#include "tls_parser.hpp"
#include <endian.h>

namespace ipxp {
TLSParser::TLSParser()
{
   tls_hs = NULL;
}

uint64_t quic_get_variable_length(uint8_t *start, uint64_t &offset)
{
   // find out length of parameter field (and load parameter, then move offset) , defined in:
   // https://www.rfc-editor.org/rfc/rfc9000.html#name-summary-of-integer-encoding
   // this approach is used also in length field , and other QUIC defined fields.
   uint64_t tmp = 0;

   uint8_t two_bits = *(start + offset) & 0xC0;

   switch (two_bits) {
       case 0:
          tmp     = *(start + offset) & 0x3F;
          offset += sizeof(uint8_t);
          return tmp;

       case 64:
          tmp     = be16toh(*(uint16_t *) (start + offset)) & 0x3FFF;
          offset += sizeof(uint16_t);
          return tmp;

       case 128:
          tmp     = be32toh(*(uint32_t *) (start + offset)) & 0x3FFFFFFF;
          offset += sizeof(uint32_t);
          return tmp;

       case 192:
          tmp     = be64toh(*(uint64_t *) (start + offset)) & 0x3FFFFFFFFFFFFFFF;
          offset += sizeof(uint64_t);
          return tmp;

       default:
          return 0;
   }
} // quic_get_variable_length

bool TLSParser::tls_is_grease_value(uint16_t val)
{
   if (val != 0 && !(val & ~(0xFAFA)) && ((0x00FF & val) == (val >> 8))) {
      return true;
   }
   return false;
}

void TLSParser::tls_get_quic_user_agent(TLSData &data, char *buffer, size_t buffer_size)
{
   // compute end of quic_transport_parameters
   const uint16_t quic_transport_params_len = ntohs(*(uint16_t *) data.start);
   const uint8_t *quic_transport_params_end = data.start + quic_transport_params_len
     + sizeof(quic_transport_params_len);

   if (quic_transport_params_end > data.end) {
      return;
   }

   uint64_t offset = 0;
   uint64_t param  = 0;
   uint64_t length = 0;

   while (data.start + offset < quic_transport_params_end) {
      param  = quic_get_variable_length((uint8_t *) data.start, offset);
      length = quic_get_variable_length((uint8_t *) data.start, offset);
      if (param == TLS_EXT_GOOGLE_USER_AGENT) {
         if (length + (size_t) 1 > buffer_size) {
            length = buffer_size - 1;
         }
         memcpy(buffer, data.start + offset, length);
         buffer[length] = 0;
         data.obejcts_parsed++;
      }
      offset += length;
   }
   return;
}

void TLSParser::tls_get_server_name(TLSData &data, char *buffer, size_t buffer_size)
{
   uint16_t list_len       = ntohs(*(uint16_t *) data.start);
   uint16_t offset         = sizeof(list_len);
   const uint8_t *list_end = data.start + list_len + offset;
   size_t buff_offset      = 0;

   if (list_end > data.end) {
      // data.valid = false;
      return;
   }

   while (data.start + sizeof(tls_ext_sni) + offset < list_end) {
      tls_ext_sni *tmp_sni = (tls_ext_sni *) (data.start + offset);
      uint16_t sni_len     = ntohs(tmp_sni->length);

      offset += sizeof(tls_ext_sni);
      if (data.start + offset + sni_len > list_end) {
         break;
      }
      if (sni_len + (size_t) 1 + buff_offset > buffer_size) {
         sni_len = buffer_size - 1 - buff_offset;
      }
      memcpy(buffer + buff_offset, data.start + offset, sni_len);

      buff_offset += sni_len + 1;
      buffer[sni_len + buff_offset] = 0;
      data.obejcts_parsed++;
      offset += ntohs(tmp_sni->length);
   }
   return;
}

void TLSParser::tls_get_alpn(TLSData &data, char *buffer, size_t buffer_size)
{
   uint16_t list_len       = ntohs(*(uint16_t *) data.start);
   uint16_t offset         = sizeof(list_len);
   const uint8_t *list_end = data.start + list_len + offset;

   if (list_end > data.end) {
      // data.valid = false;
      return;
   }
   if (buffer[0] != 0) {
      return;
   }

   uint16_t alpn_written = 0;

   while (data.start + sizeof(uint8_t) + offset < list_end) {
      uint8_t alpn_len        = *(uint8_t *) (data.start + offset);
      const uint8_t *alpn_str = data.start + offset + sizeof(uint8_t);

      offset += sizeof(uint8_t) + alpn_len;
      if (data.start + offset > list_end) {
         break;
      }
      if (alpn_written + alpn_len + (size_t) 2 >= buffer_size) {
         break;
      }

      if (alpn_written != 0) {
         buffer[alpn_written++] = ';';
      }
      memcpy(buffer + alpn_written, alpn_str, alpn_len);
      alpn_written        += alpn_len;
      buffer[alpn_written] = 0;
   }
   return;
} // TLSParser::tls_get_alpn

tls_handshake TLSParser::tls_get_handshake()
{
   if (tls_hs != NULL) {
      return *tls_hs;
   }
   return { };
}

bool TLSParser::tls_check_handshake(TLSData & payload)
{
   tls_hs = (tls_handshake *) payload.start;
   const uint8_t tmp_hs_type = tls_hs->type;

   if (payload.start + sizeof(tls_handshake) > payload.end ||
     !(tmp_hs_type == TLS_HANDSHAKE_CLIENT_HELLO || tmp_hs_type == TLS_HANDSHAKE_SERVER_HELLO)) {
      return false;
   }
   if (payload.start + 44 > payload.end ||
     tls_hs->version.major != 3 ||
     tls_hs->version.minor < 1 ||
     tls_hs->version.minor > 3) {
      return false;
   }
   payload.start += sizeof(tls_handshake);
   return true;
}

bool TLSParser::tls_check_rec(TLSData & payload)
{
   tls_rec *tls = (tls_rec *) payload.start;

   if (payload.start + sizeof(tls_rec) > payload.end || !tls || tls->type != TLS_HANDSHAKE ||
     tls->version.major != 3 || tls->version.minor > 3) {
      return false;
   }
   payload.start += sizeof(tls_rec);
   return true;
}

bool TLSParser::tls_skip_random(TLSData& payload)
{
   if (payload.start + 32 > payload.end) {
      return false;
   }
   payload.start += 32;
   return true;
}

bool TLSParser::tls_skip_sessid(TLSData& payload)
{
   uint8_t sess_id_len = *(uint8_t *) payload.start;

   if (payload.start + sizeof(sess_id_len) + sess_id_len > payload.end) {
      return false;
   }
   payload.start += sizeof(sess_id_len) + sess_id_len;
   return true;
}

bool TLSParser::tls_skip_cipher_suites(TLSData& payload)
{
   uint16_t cipher_suite_len = ntohs(*(uint16_t *) payload.start);

   if (payload.start + sizeof(cipher_suite_len) + +cipher_suite_len > payload.end) {
      return false;
   }
   payload.start += sizeof(cipher_suite_len) + cipher_suite_len;
   return true;
}

bool TLSParser::tls_skip_compression_met(TLSData& payload)
{
   uint8_t compression_met_len = *(uint8_t *) payload.start;

   if (payload.start + sizeof(compression_met_len) + compression_met_len > payload.end) {
      return false;
   }
   payload.start += sizeof(compression_met_len) + compression_met_len;
   return true;
}

bool TLSParser::tls_check_ext_len(TLSData& payload)
{
   const uint8_t *ext_end = payload.start + ntohs(*(uint16_t *) payload.start) + sizeof(uint16_t);

   payload.start += 2;
   if (ext_end > payload.end) {
      return false;
   }
   if (ext_end <= payload.end) {
      payload.end = ext_end;
   }
   return true;
}

bool TLSParser::tls_get_ja3_cipher_suites(std::string &ja3, TLSData &data)
{
   uint16_t cipher_suites_length = ntohs(*(uint16_t *) data.start);
   uint16_t type_id = 0;
   const uint8_t *section_end = data.start + cipher_suites_length;

   if (data.start + cipher_suites_length + 1 > data.end) {
      // data.valid = false;
      return false;
   }
   data.start += sizeof(cipher_suites_length);

   for (; data.start <= section_end; data.start += sizeof(uint16_t)) {
      type_id = ntohs(*(uint16_t *) (data.start));
      if (!tls_is_grease_value(type_id)) {
         ja3 += std::to_string(type_id);
         if (data.start < section_end) {
            ja3 += '-';
         }
      }
   }
   ja3 += ',';
   return true;
}

std::string TLSParser::tls_get_ja3_ecpliptic_curves(TLSData &data)
{
   std::string collected_types;
   uint16_t type_id        = 0;
   uint16_t list_len       = ntohs(*(uint16_t *) data.start);
   const uint8_t *list_end = data.start + list_len + sizeof(list_len);
   uint16_t offset         = sizeof(list_len);

   if (list_end > data.end) {
      // data.valid = false;
      return "";
   }

   while (data.start + sizeof(uint16_t) + offset <= list_end) {
      type_id = ntohs(*(uint16_t *) (data.start + offset));
      offset += sizeof(uint16_t);
      if (!tls_is_grease_value(type_id)) {
         collected_types += std::to_string(type_id);

         if (data.start + sizeof(uint16_t) + offset <= list_end) {
            collected_types += '-';
         }
      }
   }
   return collected_types;
}

std::string TLSParser::tls_get_ja3_ec_point_formats(TLSData &data)
{
   std::string collected_formats;
   uint8_t list_len        = *data.start;
   uint16_t offset         = sizeof(list_len);
   const uint8_t *list_end = data.start + list_len + offset;
   uint8_t format;

   if (list_end > data.end) {
      // data.valid = false;
      return "";
   }

   while (data.start + sizeof(uint8_t) + offset <= list_end) {
      format = *(data.start + offset);
      collected_formats += std::to_string((int) format);
      offset += sizeof(uint8_t);
      if (data.start + sizeof(uint8_t) + offset <= list_end) {
         collected_formats += '-';
      }
   }
   return collected_formats;
}
}
