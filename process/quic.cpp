/**
 * \file quic.cpp
 * \brief Plugin for parsing quic traffic.
 * \author andrej lukacovic lukacan1@fit.cvut.cz
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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
#include <sstream>
#include <endian.h>

#include <openssl/kdf.h>
#include <openssl/evp.h>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include <ipfixprobe/byte-utils.hpp>

#include "quic.hpp"


namespace ipxp {

int RecordExtQUIC::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("quic", [](){return new QUICPlugin();});
   register_plugin(&rec);
   RecordExtQUIC::REGISTERED_ID = register_extension();
}


// Print debug message if debugging is allowed.


#define DEBUG_QUIC 1
#ifdef  DEBUG_QUIC
# define DEBUG_MSG(format, ...) fprintf(stderr, format, ## __VA_ARGS__)
#else
# define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_QUIC
# define DEBUG_CODE(code) code
#else
# define DEBUG_CODE(code)
#endif


QUICPlugin::QUICPlugin()
{
   quic_h1 = nullptr;
   quic_h2 = nullptr;

   header  = nullptr;
   payload = nullptr;

   header_len  = 0;
   payload_len = 0;

   dcid   = nullptr;
   scid   = nullptr;
   pkn    = nullptr;
   sample = nullptr;


   memset(decrypted_payload,0,1500);
   memset(assembled_payload,0,1500);
   //decrypted_payload = nullptr;
   decrypt_buffer_len = 0;
   
   //assembled_payload = nullptr;
   assemble_buffer_len = 0;
   
   final_payload = nullptr;
   

   parsed_initial = 0;
   quic_ptr = nullptr;


   google_QUIC = false;
}

QUICPlugin::~QUICPlugin()
{
   close();
}

void QUICPlugin::init(const char *params)
{
}

void QUICPlugin::close()
{
   if (quic_ptr != nullptr) {
      delete quic_ptr;
   }
   quic_ptr = nullptr;
}

ProcessPlugin *QUICPlugin::copy()
{
   return new QUICPlugin(*this);
}



uint64_t quic_get_variable_length(uint8_t * start , uint64_t &offset)
{
   // find out length of parameter field (and load parameter, then move offset) , defined in:
   // https://www.rfc-editor.org/rfc/rfc9000.html#name-summary-of-integer-encoding
   // this approach is used also in length field , and other QUIC defined fields.
   uint64_t tmp = 0;

   uint8_t two_bits = *(start + offset) & 0xC0;
   switch (two_bits) {
   case 0:
      tmp = *(start + offset) & 0x3F;
      offset += sizeof(uint8_t);
      return tmp;
   case 64:
      tmp = be16toh(*(uint16_t*)(start + offset)) & 0x3FFF;
      offset += sizeof(uint16_t);
      return tmp;
   case 128:
      tmp = be32toh(*(uint32_t*)(start + offset)) & 0x3FFFFFFF;
      offset += sizeof(uint32_t);
      return tmp;
   case 192:
      tmp = be64toh(*(uint64_t*)(start + offset)) & 0x3FFFFFFFFFFFFFFF;
      offset += sizeof(uint64_t);
      return tmp;
   default:
      return 0;
   }

   
}



// --------------------------------------------------------------------------------------------------------------------------------
// PARSE CRYPTO PAYLOAD
// --------------------------------------------------------------------------------------------------------------------------------
void get_tls_user_agent(my_payload_data &data, uint16_t length_ext, char *out, size_t bufsize)
{

   // compute end of quic_transport_parameters
   const char *quic_transport_params_end = data.data + length_ext;
   
   uint64_t offset = 0;
   uint64_t param = 0;
   uint64_t length = 0;

   while (data.data + offset < quic_transport_params_end) {

      param = quic_get_variable_length((uint8_t*)data.data,offset);


      length = quic_get_variable_length((uint8_t*)data.data,offset);


      // check if this parameter is TLS_EXT_GOOGLE_USER_AGENT which contains user agent
      if (param == TLS_EXT_GOOGLE_USER_AGENT) {
         if (length + (size_t) 1 > bufsize) {
            length = bufsize - 1;
         }
         memcpy(out, data.data + offset, length);
         out[length] = 0; 
         data.user_agent_parsed++;
      }

      // move offset after this parameter and check next parameter until ond of extension field
      offset += length;
   }
}

void get_tls_server_name(my_payload_data &data, char *out, size_t bufsize)
{      
   uint16_t list_len    = ntohs(*(uint16_t *) data.data);
   uint16_t offset      = sizeof(list_len);
   
   const char *list_end = data.data + list_len + offset;

   if (list_end > data.end) {
      data.valid = false;
      return;
   }

   while (data.data + sizeof(tls_ext_sni) + offset < list_end) {
      tls_ext_sni *sni = (tls_ext_sni *) (data.data + offset);
      uint16_t sni_len = ntohs(sni->length);

      offset += sizeof(tls_ext_sni);
      if (data.data + offset + sni_len > list_end) {
         break;
      }
      if (out[0] != 0) {
         break;
      }
      if (sni_len + (size_t) 1 > bufsize) {
         sni_len = bufsize - 1;
      }
      memcpy(out, data.data + offset, sni_len);
      out[sni_len] = 0;
      data.sni_parsed++;
      offset += ntohs(sni->length);
   }
}

bool is_grease_value_(uint16_t val)
{
   if (val != 0 && !(val & ~(0xFAFA)) && ((0x00FF & val) == (val >> 8))) {
      return true;
   }
   return false;
}

void get_ja3_cipher_suites(std::string &ja3, my_payload_data &data)
{
   int cipher_suites_length = ntohs(*(uint16_t *) data.data);
   uint16_t type_id         = 0;
   const char *section_end  = data.data + cipher_suites_length;

   if (data.data + cipher_suites_length + 1 > data.end) {
      data.valid = false;
      return;
   }
   data.data += 2;

   for (; data.data <= section_end; data.data += sizeof(uint16_t)) {
      type_id = ntohs(*(uint16_t *) (data.data));
      if (!is_grease_value_(type_id)) {
         ja3 += std::to_string(type_id);
         if (data.data < section_end) {
            ja3 += '-';
         }
      }
   }
   ja3 += ',';
}

bool parse_tls_nonext_hdr(my_payload_data &payload, std::string *ja3)
{
   tls_handshake *tls_hs = (tls_handshake *) payload.data;
   const uint8_t hs_type = tls_hs->type;
   if (payload.data + sizeof(tls_handshake) > payload.end ||
      !(hs_type == TLS_HANDSHAKE_CLIENT_HELLO || hs_type == TLS_HANDSHAKE_SERVER_HELLO)) {
      return false;
   }

   //uint32_t hs_len = tls_hs->length1 << 16 | ntohs(tls_hs->length2);

   // 1 + 3 + 2 + 32 + 1 + 2 + 1 + 2 = 44
   // type + length + version + random + sessionid + ciphers + compression + ext-len
   if (payload.data + 44 > payload.end 
      || tls_hs->version.major != 3 
      || tls_hs->version.minor < 1 
      || tls_hs->version.minor > 3) {
      return false;
   }
   payload.data += sizeof(tls_handshake);

   if (ja3) {
      *ja3 += std::to_string((uint16_t) tls_hs->version.version) + ',';
   }

   payload.data += 32; // Skip random

   int tmp = *(uint8_t *) payload.data;
   if (payload.data + tmp + 2 > payload.end) {
      return false;
   }
   payload.data += tmp + 1; // Skip session id

   if (hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
      if (ja3) {
         get_ja3_cipher_suites(*ja3, payload);
         if (!payload.valid) {
            return false;
         }
      } else {
         if (payload.data + 2 > payload.end) {
            return false;
         }
         payload.data += ntohs(*(uint16_t *) payload.data) + 2; // Skip cipher suites
      }

      tmp = *(uint8_t *) payload.data;
      if (payload.data + tmp + 3 > payload.end) { // check space for (1+tmp) bytes of compression + next 2 bytes of exts length
         return false;
      }
      payload.data += tmp + 1; // Skip compression methods
   } else {
      /* TLS_HANDSHAKE_SERVER_HELLO */
      payload.data += 2; // Skip cipher suite
      payload.data += 1; // Skip compression method
   }

   const char *ext_end = payload.data + ntohs(*(uint16_t *) payload.data) + 2;
   payload.data += 2;
   if (ext_end <= payload.end) {
      payload.end = ext_end;
   }

   return true;
}

bool QUICPlugin::parse_tls(RecordExtQUIC *rec)
{
   my_payload_data payload = {
      (char *) final_payload,
      (char *) final_payload + payload_len,
      true,
      0,
      0
   };

   tls_rec_lay *tls = (tls_rec_lay *) payload.data;
   payload.data += sizeof(tls_rec_lay);
   if (payload_len < sizeof(tls_rec_lay) || tls->type != CRYPTO_FRAME) {
      DEBUG_MSG("Frame inside Initial packet is not of type CRYPTO\n");
      return false;
   }

   if (!parse_tls_nonext_hdr(payload, nullptr)) {
      DEBUG_MSG("Could not parse TLS header\n");
      return false;
   }

   while (payload.data + sizeof(QUIC_EXT) <= payload.end) {
      QUIC_EXT *ext   = (QUIC_EXT *) payload.data;
      uint16_t type   = ntohs(ext->type);
      uint16_t length = ntohs(ext->length);

      payload.data += sizeof(QUIC_EXT);

      if (type == TLS_EXT_SERVER_NAME) {
         get_tls_server_name(payload, rec->sni, sizeof(rec->sni));
         parsed_initial += payload.sni_parsed;
      } else if (type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1 
                 || type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS 
                 || type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V2) {
         get_tls_user_agent(payload,length ,rec->user_agent, sizeof(rec->user_agent));
         parsed_initial += payload.user_agent_parsed;
      }
      if (!payload.valid) {
         return false;
      }
      payload.data += length;
   }
   return payload.sni_parsed != 0 || payload.user_agent_parsed != 0;
} // QUICPlugin::parse_tls

// --------------------------------------------------------------------------------------------------------------------------------
// DECRYTP HEADER AND PAYLOAD
// --------------------------------------------------------------------------------------------------------------------------------

bool QUICPlugin::expand_label(const char *label_prefix, const char *label, const uint8_t *context_hash,
  uint8_t context_length, uint16_t desired_len, uint8_t *out, uint8_t &out_len)
{
   /* HKDF-Expand-Label(Secret, Label, Context, Length) =
    *      HKDF-Expand(Secret, HkdfLabel, Length)
    *
    * Where HkdfLabel is specified as:
    *
    * struct {
    *     uint16 length = Length;
    *     opaque label<7..255> = "tls13 " + Label;
    *     opaque context<0..255> = Context;
    * } HkdfLabel;
    *
    *
    * https://datatracker.ietf.org/doc/html/rfc8446#section-3.4
    * "... the actual length precedes the vector's contents in the byte stream ... "
    * */

   const unsigned int label_prefix_length = (unsigned int) strlen(label_prefix);
   const unsigned int label_length        = (unsigned int) strlen(label);


   const uint8_t label_vector_length = label_prefix_length + label_length;
   const uint16_t length = ntohs(desired_len);

   out_len = sizeof(length) + sizeof(label_vector_length) + label_vector_length + sizeof(context_length);


   // copy length
   memcpy(out, &length, sizeof(length));
   // copy whole label length as described above
   memcpy(out + sizeof(length), &label_vector_length, sizeof(label_vector_length));
   // copy label prefix ("tls13 ")
   memcpy(out + sizeof(length) + sizeof(label_vector_length), label_prefix, label_prefix_length);
   // copy actual label
   memcpy(out + sizeof(length) + sizeof(label_vector_length) + label_prefix_length, label, label_length);
   // copy context length (should be 0)
   memcpy(out + sizeof(length) + sizeof(label_vector_length) + label_prefix_length + label_length, &context_length,
     sizeof(context_length));

   return true;
}

bool QUICPlugin::quic_derive_n_set(uint8_t *secret, uint8_t *expanded_label, uint8_t size, size_t output_len,
  uint8_t *store_data)
{
   EVP_PKEY_CTX *pctx;

   pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
   if (1 != EVP_PKEY_derive_init(pctx)) {
      DEBUG_MSG("Error, context initialization failed %s\n", (char *) expanded_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
      DEBUG_MSG("Error, mode initialization failed %s\n", (char *) expanded_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())) {
      DEBUG_MSG("Error, message digest initialization failed %s\n", (char *) expanded_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx, expanded_label, size)) {
      DEBUG_MSG("Error, info initialization failed %s\n", (char *) expanded_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, HASH_SHA2_256_LENGTH)) {
      DEBUG_MSG("Error, key initialization failed %s\n", (char *) expanded_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_derive(pctx, store_data, &output_len)) {
      DEBUG_MSG("Error, HKDF-Expand derivation failed %s\n", (char *) expanded_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   EVP_PKEY_CTX_free(pctx);
   return true;
} // QUICPlugin::quic_derive_n_set

bool QUICPlugin::quic_derive_secrets(uint8_t *secret)
{
   uint8_t len_quic_key;
   uint8_t len_quic_iv;
   uint8_t len_quic_hp;


   // expand label for other initial secrets
   expand_label("tls13 ", "quic key", NULL, 0, 16, quic_key, len_quic_key);
   expand_label("tls13 ", "quic iv", NULL, 0, 12, quic_iv, len_quic_iv);
   expand_label("tls13 ", "quic hp", NULL, 0, 16, quic_hp, len_quic_hp);


   // use HKDF-Expand to derive other secrets
   if (!quic_derive_n_set(secret, quic_key, len_quic_key, AES_128_KEY_LENGTH, initial_secrets.key) 
       || !quic_derive_n_set(secret, quic_iv, len_quic_iv, TLS13_AEAD_NONCE_LENGTH, initial_secrets.iv) 
       || !quic_derive_n_set(secret, quic_hp, len_quic_hp, AES_128_KEY_LENGTH, initial_secrets.hp)) {
      DEBUG_MSG("Error, derivation of initial secrets failed\n");
      return false;
   }
   return true;
} // QUICPlugin::quic_derive_secrets

uint8_t QUICPlugin::quic_draft_version(uint32_t version)
{
   if ((version >> 8) == 0xff0000) {
      return (uint8_t) version;
   }

   switch (version) {
   case (0xfaceb001):
      return 22;
   case 0xfaceb002:
   case 0xfaceb00e:
   case 0x51303530:
   case 0x54303530:
   case 0x54303531:
      return 27;
   case (0x0a0a0a0a & 0x0F0F0F0F):
      return 29;
   case 0x00000001:
      return 33;
   default:
      return 0;
   }
}

bool QUICPlugin::quic_check_version(uint32_t version, uint8_t max_version)
{
   uint8_t draft_version = quic_draft_version(version);

   return draft_version && draft_version <= max_version;
}

bool QUICPlugin::quic_create_initial_secrets(CommSide side,RecordExtQUIC * rec)
{
   uint32_t version = quic_h1->version;

   version = ntohl(version);
   rec->quic_version = version;

   static const uint8_t handshake_salt_draft_22[SALT_LENGTH] = {
      0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
      0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a
   };
   static const uint8_t handshake_salt_draft_23[SALT_LENGTH] = {
      0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
      0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
   };
   static const uint8_t handshake_salt_draft_29[SALT_LENGTH] = {
      0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
      0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
   };
   static const uint8_t handshake_salt_v1[SALT_LENGTH] = {
      0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
      0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
   };
   static const uint8_t hanshake_salt_draft_q50[SALT_LENGTH] = {
      0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
      0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45
   };
   static const uint8_t hanshake_salt_draft_t50[SALT_LENGTH] = {
      0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80,
      0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10
   };
   static const uint8_t hanshake_salt_draft_t51[SALT_LENGTH] = {
      0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50,
      0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d
   };


   const uint8_t *salt;


   // these three are Google QUIC version
   if (version == 0x51303530) {
      salt = hanshake_salt_draft_q50;
      google_QUIC = true;
   } else if (version == 0x54303530) {
      salt = hanshake_salt_draft_t50;
      google_QUIC = true;
   } else if (version == 0x54303531) {
      salt = hanshake_salt_draft_t51;
      google_QUIC = true;
   } else if (quic_check_version(version, 22)) {
      salt = handshake_salt_draft_22;
      google_QUIC = false;
   } else if (quic_check_version(version, 28)) {
      salt = handshake_salt_draft_23;
      google_QUIC = false;
   } else if (quic_check_version(version, 32)) {
      salt = handshake_salt_draft_29;
      google_QUIC = false;
   } else {
      salt = handshake_salt_v1;
      google_QUIC = false;
   }


   uint8_t extracted_secret[HASH_SHA2_256_LENGTH] = { 0 };
   uint8_t expanded_secret[HASH_SHA2_256_LENGTH]  = { 0 };
   size_t expd_len = HASH_SHA2_256_LENGTH;
   size_t extr_len = HASH_SHA2_256_LENGTH;

   uint8_t *expand_label_buffer = nullptr;
   uint8_t expand_label_len;

   uint8_t *cid    = nullptr;
   uint8_t cid_len = 0;

   if (side == CommSide::CLIENT_IN) {
      expand_label_buffer = client_In_Buffer;
      cid     = dcid;
      cid_len = quic_h1->dcid_len;
   } else if (side == CommSide::SERVER_IN) {
      expand_label_buffer = server_In_Buffer;
      cid     = scid;
      cid_len = quic_h2->scid_len;
   } else {
      throw PluginError("invalid communication side param");
   }


   // HKDF-Extract
   EVP_PKEY_CTX *pctx;

   pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
   if (1 != EVP_PKEY_derive_init(pctx)) {
      DEBUG_MSG("Error, context initialization failed(Extract)\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)) {
      DEBUG_MSG("Error, mode initialization failed(Extract)\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())) {
      DEBUG_MSG("Error, message digest initialization failed(Extract)\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, SALT_LENGTH)) {
      DEBUG_MSG("Error, salt initialization failed(Extract)\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, cid, cid_len)) {
      DEBUG_MSG("Error, key initialization failed(Extract)\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_derive(pctx, extracted_secret, &extr_len)) {
      DEBUG_MSG("Error, HKDF-Extract derivation failed\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }


   // Expand-Label
   char *labels[] = {"client in", "server in"};
   static_assert(static_cast<size_t>(CommSide::CLIENT_IN) == 0, "Dependency check failed");
   expand_label("tls13 ", labels[static_cast<size_t>(side)], NULL, 0, HASH_SHA2_256_LENGTH, expand_label_buffer, expand_label_len);

   // HKDF-Expand
   if (!EVP_PKEY_derive_init(pctx)) {
      DEBUG_MSG("Error, context initialization failed(Expand)\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
      DEBUG_MSG("Error, mode initialization failed(Expand)\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())) {
      DEBUG_MSG("Error, message digest initialization failed(Expand)\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx, expand_label_buffer, expand_label_len)) {
      DEBUG_MSG("Error, info initialization failed(Expand)\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, extracted_secret, HASH_SHA2_256_LENGTH)) {
      DEBUG_MSG("Error, key initialization failed(Expand)\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_derive(pctx, expanded_secret, &expd_len)) {
      DEBUG_MSG("Error, HKDF-Expand derivation failed\n");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   EVP_PKEY_CTX_free(pctx);

   
   // Derive other secrets
   if (!quic_derive_secrets(expanded_secret)) {
      DEBUG_MSG("Error, Derivation of initial secrets failed\n");
      return false;
   }

   // Setup nonce for payload decryption
   memcpy(nonce, initial_secrets.iv, TLS13_AEAD_NONCE_LENGTH);
   return true;
} // QUICPlugin::quic_create_initial_secrets

bool QUICPlugin::quic_decrypt_header()
{
   uint8_t plaintext[SAMPLE_LENGTH];
   uint8_t mask[5]     = { 0 };
   uint8_t full_pkn[4] = { 0 };
   int len = 0;
   uint8_t first_byte     = 0;
   uint32_t packet_number = 0;


   // Encrypt sample with AES-ECB. Encrypted sample is used in XOR with packet header
   EVP_CIPHER_CTX *ctx;

   if (!(ctx = EVP_CIPHER_CTX_new())) {
      DEBUG_MSG("Sample encryption, creating context failed\n");
      return false;
   }
   if (!(EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, initial_secrets.hp, NULL))) {
      DEBUG_MSG("Sample encryption, context initialization failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }


   // set padding always returns 1 so no need for success
   // we need to disable padding so we can use EncryptFinal

   EVP_CIPHER_CTX_set_padding(ctx, 0);
   if (!(EVP_EncryptUpdate(ctx, plaintext, &len, sample, SAMPLE_LENGTH))) {
      DEBUG_MSG("Sample encryption, decrypting header failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!(EVP_EncryptFinal_ex(ctx, plaintext + len, &len))) {
      DEBUG_MSG("Sample encryption, final header decryption failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }

   EVP_CIPHER_CTX_free(ctx);
   // basically we create mask, as shown in code belove
   memcpy(mask, plaintext, sizeof(mask));

   // https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection-applicati

   /* 
      code belove shows a sample algorithm for applying header protection.

      mask = header_protection(hp_key, sample)

      pn_length = (packet[0] & 0x03) + 1
      
      if (packet[0] & 0x80) == 0x80:
         # Long header: 4 bits masked
         packet[0] ^= mask[0] & 0x0f
      else:
         # Short header: 5 bits masked
         packet[0] ^= mask[0] & 0x1f
      
   */

   
   
   // we do not have to handle short header, Initial packets have only long header

   first_byte  = quic_h1->first_byte;
   first_byte ^= mask[0] & 0x0f;
   uint8_t pkn_len = (first_byte & 0x03) + 1;

   // set deobfuscated first byte
   header[0] = first_byte;


   // now we know pkn length, so copy pkn into buffer
   memcpy(&full_pkn, pkn, pkn_len);


   // we now de-obsfuscate pkn
   for (unsigned int i = 0; i < pkn_len; i++) {
      packet_number |= (full_pkn[i] ^ mask[1 + i]) << (8 * (pkn_len - 1 - i));
   }


   // after de-obfuscating pkn, we know exactly pkn length so we can correctly adjust start of payload
   payload     = payload + pkn_len;
   payload_len = payload_len - pkn_len;

   // SET HEADER LENGTH, if header length is set incorrectly AEAD will calculate wrong tag, so decryption will fail
   header_len = payload - header;

   // set decrypted packet number
   for (unsigned i = 0; i < pkn_len; i++) {
      header[header_len - 1 - i] = (uint8_t) (packet_number >> (8 * i));
   }


   // adjust nonce for payload decryption
   // https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
   //  The exclusive OR of the padded packet number and the IV forms the AEAD nonce
   phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ packet_number);

   return true;
} // QUICPlugin::quic_decrypt_header




bool QUICPlugin::quic_decrypt_payload()
{
   uint8_t atag[16] = { 0 };
   int len;


   /* Input is --> "header || ciphertext (buffer) || auth tag (16 bytes)" */

   if (payload_len <= 16) {
      DEBUG_MSG("Payload decryption error, ciphertext too short\n");
      return false;
   }

   // https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-34#section-5.3
   // "These cipher suites have a 16-byte authentication tag and produce an output 16 bytes larger than their input."

   // adjust length because last 16 bytes are authentication tag
   payload_len -= 16;
   // set tag based on last 16 bytes
   memcpy(&atag, &payload[payload_len], 16);


   EVP_CIPHER_CTX *ctx;

   
   if (!(ctx = EVP_CIPHER_CTX_new())) {
      DEBUG_MSG("Payload decryption error, creating context failed\n");
      return false;
   }
   if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
      DEBUG_MSG("Payload decryption error, context initialization failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, TLS13_AEAD_NONCE_LENGTH, NULL)) {
      DEBUG_MSG("Payload decryption error, setting NONCE length failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }

   // SET NONCE and KEY
   if (!EVP_DecryptInit_ex(ctx, NULL, NULL, initial_secrets.key, nonce)) {
      DEBUG_MSG("Payload decryption error, setting KEY and NONCE failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }

   // SET ASSOCIATED DATA (HEADER with unprotected PKN)
   if (!EVP_DecryptUpdate(ctx, NULL, &len, header, header_len)) {
      DEBUG_MSG("Payload decryption error, initializing authenticated data failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!EVP_DecryptUpdate(ctx, decrypted_payload, &len, payload, payload_len)) {
      DEBUG_MSG("Payload decryption error, decrypting payload failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, atag)) {
      DEBUG_MSG("Payload decryption error, TAG check failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!EVP_DecryptFinal_ex(ctx, decrypted_payload + len, &len)) {
      DEBUG_MSG("Payload decryption error, final payload decryption failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }

   EVP_CIPHER_CTX_free(ctx);

   final_payload = decrypted_payload;
   return true;
} // QUICPlugin::quic_decrypt_payload

// --------------------------------------------------------------------------------------------------------------------------------
// WORK WITH DATA
// --------------------------------------------------------------------------------------------------------------------------------




bool QUICPlugin::quic_assemble()
{

   assembled_payload[0] = 0x06;
   

   // set end of payload
   uint8_t * payload_end = decrypted_payload + payload_len;

   uint64_t offset = 0;
   uint64_t frame_offset = 0;
   uint64_t frame_length = 0;


   // loop through whole padding, the logic is check first fragment (check type and length), if it`s of type crypto
   // copy the frame into the buffer at offset which is defined in the frame, then skip length bytes, so we jump
   // to the next fragment, this process repeat till the end of payload. If the frame is not of type crypto, we 
   // skip only one byte, this is because for example padding fragments have no defined length, so we dont know
   // how much bytes we have to skip, on the other hand ping frames have only 1 byte in length.
   // In initial packets this types of frames can occure: Crypto, Padding, Ping, ACK, CONNECTION_CLOSE  
   while (decrypted_payload + offset < payload_end) {
      // process of computing offset length and length field length, is same as above in extracting user agent
      if (*(decrypted_payload + offset) == CRYPTO) {
         offset += 1;

         frame_offset = quic_get_variable_length(decrypted_payload,offset);
         frame_length = quic_get_variable_length(decrypted_payload,offset);

         // beware this part is tricky, tls parse data expects 4 bytes at the start of crypto frame (type(1), offset(1), length(2))
         // BUT google quic uses variable length of some fields (more precisely length can have variable length), we consider that
         // length field have 2 bytes, this is not wrong because length is not used in tls parse date.
         if (assembled_payload + frame_offset + 4 * sizeof(uint8_t) < assembled_payload + 1500  
            && decrypted_payload + offset < payload_end
            && assembled_payload + frame_offset + 4 * sizeof(uint8_t) + frame_length < assembled_payload + 1500)
         {
            memcpy(assembled_payload + frame_offset + 4 * sizeof(uint8_t), decrypted_payload + offset, frame_length);
            offset += frame_length;
         } else {
            return false;
         }
      // https://www.rfc-editor.org/rfc/rfc9000.html#name-frames-and-frame-types
      // only those frames can occure in initial packets
      } else if (*(decrypted_payload + offset) == PADDING 
                 || *(decrypted_payload + offset) == PING 
                 || *(decrypted_payload + offset) == ACK1 
                 || *(decrypted_payload + offset) == ACK2 
                 || *(decrypted_payload + offset) == CONNECTION_CLOSE)
      {
         offset++;
      } else{
         DEBUG_MSG("Wrong Frame type read during frames assemble\n");
         return false;
      }
   }
   final_payload = assembled_payload;
   return true;
}

bool QUICPlugin::quic_parse_data(const Packet &pkt)
{
   
   
   uint8_t *tmp_pointer       = (uint8_t *) pkt.payload;
   uint64_t offset = 0;
   const uint8_t *payload_end = (uint8_t *) pkt.payload + pkt.payload_len;

   
   
   // set header pointer to the start of header
   header = (uint8_t *) (tmp_pointer + offset); // set header pointer

   
   
   
   // pointer to the first byte, version and dcid length
   quic_h1 = (quic_header1 *) (tmp_pointer + offset);


   if (quic_h1->version == 0x0) {
      return false;
   }

   offset += sizeof(quic_header1);



   if ((tmp_pointer + offset) > payload_end) {
      return false;
   }

   
   
   // if dcid length is not zero , read dcid
   if (quic_h1->dcid_len != 0) {
      dcid = (tmp_pointer + offset);
      offset += quic_h1->dcid_len;
   }

   if ((tmp_pointer + offset) > payload_end) {
      return false;
   }
   

   // after dcid is scid length, so read scid length
   quic_h2 = (quic_header2 *) (tmp_pointer + offset);

   offset += sizeof(quic_header2);
   
   if ((tmp_pointer + offset) > payload_end) {
      return false;
   }


   // if scid length is not zero, read scid
   if (quic_h2->scid_len != 0) { 
      scid = (tmp_pointer + offset);
      offset += quic_h2->scid_len;
   }
   
   if ((tmp_pointer + offset) > payload_end) {
      return false;
   }


   // token length has variable length based on first two bits, after this offset should point to the token
   uint64_t token_length = quic_get_variable_length(tmp_pointer,offset);

   if ((tmp_pointer + offset) > payload_end) {
      return false;
   }
   
   // after this offset should point after the token
   offset += token_length;

   if ((tmp_pointer + offset) > payload_end) {
      return false;
   }


   // same as token length, payload length has variable length, after this offset should point to the packet number
   payload_len = quic_get_variable_length(tmp_pointer,offset);

   if ((tmp_pointer + offset) > payload_end) {
      return false;
   }


   // read packet number
   pkn = (tmp_pointer + offset);


   // read payload, we do not know packet number length, so payload will be adjusted later (after de-obfuscating header)
   payload = (tmp_pointer + offset);

   
   // read sample, sample is always assuming that packet number has length 4 bytes, so we do not need to know exact pkn length for reading sample.
   offset += sizeof(uint8_t) * 4;
   sample = (tmp_pointer + offset);

   if ((tmp_pointer + offset) > payload_end) {
      return false;
   }


   /* DO NOT SET header length this way , if packet contains more frames , pkt.payload_len is length of whole quic packet (so it contains length of all frames inside packet)
    *  so then header length is not computed correctly. Instead of this approach calculate header length after de-obfuscating packet number , this will ensure header length is computed correctly
    */
   // header_len = pkt.payload_len - payload_len;

   return true;
} // QUICPlugin::quic_parse_data

bool QUICPlugin::quic_check_initial(uint8_t packet0)
{
   // check if packet has LONG HEADER form (& 0x80 == 0x80) and is type INITIAL (& 0x30 == 0x00).
   return (packet0 & 0xB0) == 0x80;
}

bool QUICPlugin::process_quic(RecordExtQUIC *quic_data, const Packet &pkt)
{
   
   // check if packet contains LONG HEADER and is of type INITIAL
   if (pkt.ip_proto != 17 || !quic_check_initial(pkt.payload[0])) {
      DEBUG_MSG("Packet is not Initial or does not contains LONG HEADER\n");
      return false;
   }


   // header data extraction can extract data for both sides (client and server side), the differece is that server side header contains SCID length and so SCID.
   if (!quic_parse_data(pkt)) {
      return false;
   }

   // check port a.k.a direction, Server side does not contain ClientHello packets so neither SNI, but implemented for future expansion
   if (pkt.dst_port == 443) {
      if (!quic_create_initial_secrets(CommSide::CLIENT_IN,quic_data)) {
         DEBUG_MSG("Error, creation of initial secrets failed (client side)\n");
         return false;
      }
      if (!quic_decrypt_header()) {
         DEBUG_MSG("Error, header decryption failed (client side)\n");
         return false;
      }
      if (!quic_decrypt_payload()) {
         DEBUG_MSG("Error, payload decryption failed (client side)\n");
         return false;
      }
      if (!google_QUIC && !quic_assemble())
      {
         DEBUG_MSG("Error, reassembling of crypto frames failed (client side)\n");
         return false;
      }
      if (!google_QUIC && !parse_tls(quic_data))
      {
         DEBUG_MSG("SNI and User Agent Extraction failed\n");
         return false;
      }
      else {
         return true;
      }
   } else if (pkt.src_port == 443) {
      /*if (!quic_create_initial_secrets(CommSide::SERVER_IN,quic_data)) {
         DEBUG_MSG("Error, creation of initial secrets failed (server side)\n");
         return false;
      }
      if (!quic_decrypt_header()) {
         DEBUG_MSG("Error, header decryption failed (server side)\n");
         return false;
      }
      if (!quic_decrypt_payload()) {
         DEBUG_MSG("Error, payload decryption failed (server side)\n");
         return false;
      }
      if (!google_QUIC && !quic_assemble())
      {
         DEBUG_MSG("Error, reassembling of crypto frames failed (server side)\n");
         return false;
      }
      if (!google_QUIC && !parse_tls(quic_data))
      {
         DEBUG_MSG("SNI and User Agent Extraction failed\n");
         return false;
      }
      else {
         return true;
      }*/
      return true;
   }
   return false;
} // QUICPlugin::process_quic

int QUICPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int QUICPlugin::post_create(Flow &rec, const Packet &pkt)
{
   add_quic(rec, pkt);
   return 0;
}

int QUICPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int QUICPlugin::post_update(Flow &rec, const Packet &pkt)
{
   RecordExtQUIC *ext = (RecordExtQUIC *) rec.get_extension(RecordExtQUIC::REGISTERED_ID);

   if (ext == nullptr) {
      return 0;
   }

   add_quic(rec, pkt);
   return 0;
}

void QUICPlugin::add_quic(Flow &rec, const Packet &pkt)
{
   DEBUG_MSG("----- Start -----\n");
   if (quic_ptr == nullptr) {
      quic_ptr = new RecordExtQUIC();
   }

   if (process_quic(quic_ptr, pkt)) {
      std::cout << quic_ptr->sni << std::endl;
      rec.add_extension(quic_ptr);
      quic_ptr = nullptr;
   }
   DEBUG_MSG("----- End -----\n");
}

void QUICPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "QUIC plugin stats:" << std::endl;
      std::cout << "   Parsed SNI: " << parsed_initial << std::endl;
   }
}

}
