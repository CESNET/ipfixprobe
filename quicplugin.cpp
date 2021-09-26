/**
 * \file quicplugin.cpp
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
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <sstream>
#include <cstring>


#include "quicplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"


// Print debug message if debugging is allowed.
#ifdef DEBUG_QUIC
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


using namespace std;

#define QUIC_UNIREC_TEMPLATE "QUIC_SNI" /* TODO: unirec template */

UR_FIELDS(
   /* TODO: unirec fields definition */
   string QUIC_SNI
)

QUICPlugin::QUICPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;

   quic_h1 = nullptr;
   quic_h2 = nullptr;
   quic_h3 = nullptr;
   quic_h4 = nullptr;

   header  = nullptr;
   payload = nullptr;

   header_len  = 0;
   payload_len = 0;

   dcid   = nullptr;
   pkn    = nullptr;
   sample = nullptr;

   decrypted_payload = nullptr;
   plaintext_len     = 0;

   parsed_initial = 0;

   quic_ptr = nullptr;
}

QUICPlugin::QUICPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(
      plugin_options)
{
   print_stats = module_options.print_stats;

   quic_h1 = nullptr;
   quic_h2 = nullptr;
   quic_h3 = nullptr;
   quic_h4 = nullptr;

   header  = nullptr;
   payload = nullptr;

   header_len  = 0;
   payload_len = 0;

   dcid   = nullptr;
   pkn    = nullptr;
   sample = nullptr;

   decrypted_payload = nullptr;
   plaintext_len     = 0;

   parsed_initial = 0;

   quic_ptr = nullptr;
}

QUICPlugin::~QUICPlugin()
{
   if (quic_ptr != nullptr){
      delete quic_ptr;
    }
   quic_ptr = nullptr;
   quic_clean();
}

FlowCachePlugin *QUICPlugin::copy()
{
   return new QUICPlugin(*this);
}

// --------------------------------------------------------------------------------------------------------------------------------
// PARSE CRYPTO PAYLOAD
// --------------------------------------------------------------------------------------------------------------------------------

bool QUICPlugin::is_grease_value(uint16_t val)
{
   if (val != 0 && !(val & ~(0xFAFA)) && ((0x00FF & val) == (val >> 8))){
      return true;
   }
   return false;
}

void QUICPlugin::get_ja3_cipher_suites(stringstream &ja3, my_payload_data &data)
{
   int cipher_suites_length   = ntohs(*(uint16_t *) data.data);
   uint16_t type_id           = 0;
   const uint8_t *section_end = data.data + cipher_suites_length;

   if (data.data + cipher_suites_length + 1 > data.end){
      data.valid = false;
      return;
   }
   data.data += 2;

   for (; data.data <= section_end; data.data += sizeof(uint16_t)){
      type_id = ntohs(*(uint16_t *) (data.data));
      if (!is_grease_value(type_id)){
         ja3 << type_id;
         if (data.data < section_end){
            ja3 << '-';
         }
      }
   }
   ja3 << ',';
}

void QUICPlugin::get_tls_server_name(my_payload_data &data, RecordExtQUIC *rec)
{
   uint16_t list_len = ntohs(*(uint16_t *) data.data);
   uint16_t offset   = sizeof(list_len);
   uint8_t *list_end = data.data + list_len + offset;

   if (list_end > data.end){
      data.valid = false;
      return;
   }

   while (data.data + sizeof(tls_ext_sni) + offset < list_end){
      tls_ext_sni *sni = (tls_ext_sni *) (data.data + offset);
      uint16_t sni_len = ntohs(sni->length);

      offset += sizeof(tls_ext_sni);
      if (data.data + offset + sni_len > list_end){
         break;
      }

      if (rec->sni[0] != 0){
         RecordExtQUIC *tmp_rec = new RecordExtQUIC();
         rec->next = tmp_rec;
         rec       = tmp_rec;
      }
      if (sni_len + (size_t) 1 > sizeof(rec->sni)){
         sni_len = sizeof(rec->sni) - 1;
      }
      memcpy(rec->sni, data.data + offset, sni_len);
      rec->sni[sni_len] = 0;
      data.sni_parsed++;
      parsed_initial++;
      offset += ntohs(sni->length);
   }
} // QUICPlugin::get_tls_server_name

bool QUICPlugin::parse_tls(RecordExtQUIC *rec)
{
   my_payload_data payload = {
      decrypted_payload,
      decrypted_payload + payload_len,
      true,
      0
   };

   tls_rec_lay *tls = (tls_rec_lay *) payload.data;

   payload.data += sizeof(tls_rec_lay);

   if (payload_len - sizeof(tls_rec_lay) < 0 || tls->type != CRYPTO_FRAME){
      DEBUG_MSG("Frame inside Initial packet is not of type CRYPTO");
      return false;
   }

   tls_handshake *tls_hs = (tls_handshake *) payload.data;

   if (payload.data + sizeof(tls_handshake) > payload.end || tls_hs->type != CLIENT_HELLO){
      DEBUG_MSG("Content of CRYPTO frame is not Client Hello");
      return false;
   }

   uint32_t hs_len = tls_hs->length1 << 16 | ntohs(tls_hs->length2);

   if (payload.data + hs_len > payload.end || tls_hs->version.major != 3 ||
     tls_hs->version.minor < 1 || tls_hs->version.minor > 3){
      DEBUG_MSG("Wrong version");
      return false;
   }
   payload.data += sizeof(tls_handshake);

   stringstream ja3;

   ja3 << (uint16_t) tls_hs->version.version << ',';

   payload.data += 32; // Skip random

   int tmp = *(uint8_t *) payload.data;

   if (payload.data + tmp + 2 > payload.end){
      return false;
   }
   payload.data += tmp + 1; // Skip session id

   get_ja3_cipher_suites(ja3, payload);
   if (!payload.valid){
      return false;
   }

   tmp = *(uint8_t *) payload.data;
   if (payload.data + tmp + 2 > payload.end){
      return false;
   }
   payload.data += tmp + 1; // Skip compression methods

   uint8_t *ext_end = payload.data + ntohs(*(uint16_t *) payload.data);

   payload.data += 2;

   if (ext_end > payload.end){
      return false;
   }

   while (payload.data + sizeof(tls_ext) <= ext_end){
      tls_ext *ext    = (tls_ext *) payload.data;
      uint16_t length = ntohs(ext->length);
      uint16_t type   = ntohs(ext->type);

      payload.data += sizeof(tls_ext);
      if (type == TLS_EXT_SERVER_NAME){
         get_tls_server_name(payload, rec);
      }
      if (!payload.valid){
         return false;
      }
      payload.data += length;
   }
   return payload.sni_parsed != 0 || !ja3.str().empty();
} // QUICPlugin::parse_tls

// --------------------------------------------------------------------------------------------------------------------------------
// DECRYTP HEADER AND PAYLOAD
// --------------------------------------------------------------------------------------------------------------------------------

bool QUICPlugin::expand_label(const char *label_prefix, const char *label, const uint8_t *context_hash,
  uint8_t context_length, uint16_t desired_len, uint8_t *&out, uint8_t &out_len)
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
    * info = (HashLen / 256) || (HashLen % 256) || 0x21 ||
    *    "TLS 1.3, QUIC client 1-RTT secret" || 0x00*/

   const unsigned int label_prefix_length = (unsigned int) strlen(label_prefix);
   const unsigned int label_length        = (unsigned int) strlen(label);


   const uint8_t label_vector_length = label_prefix_length + label_length;
   const uint16_t length = htons(desired_len);

   out_len = label_vector_length + sizeof(length) + 2;
   out     = (uint8_t *) malloc(sizeof(uint8_t) * out_len);

   memcpy(out, &length, sizeof(length));
   memcpy(out + sizeof(length), &label_vector_length, sizeof(uint8_t));
   memcpy(out + sizeof(length) + sizeof(uint8_t), label_prefix, label_prefix_length);
   memcpy(out + sizeof(length) + sizeof(uint8_t) + label_prefix_length, label, label_length);
   memcpy(out + sizeof(length) + 1 + label_prefix_length + label_length, &context_length, 1);

   return true;
}

bool QUICPlugin::quic_derive_n_set(uint8_t *secret, uint8_t *expanded_label, uint8_t size, size_t output_len,
  uint8_t *store_data)
{
   EVP_PKEY_CTX *pctx;

   pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
   if (1 != EVP_PKEY_derive_init(pctx)){
      DEBUG_MSG("Error, context initialization failed %s", *expand_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)){
      DEBUG_MSG("Error, mode initialization failed %s", *expand_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())){
      DEBUG_MSG("Error, message digest initialization failed %s", *expand_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx, expanded_label, size)){
      DEBUG_MSG("Error, info initialization failed %s", *expand_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, HASH_SHA2_256_LENGTH)){
      DEBUG_MSG("Error, key initialization failed %s", *expand_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_derive(pctx, store_data, &output_len)){
      DEBUG_MSG("Error, HKDF-Expand derivation failed %s", *expand_label);
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   EVP_PKEY_CTX_free(pctx);
   return true;
} // QUICPlugin::quic_derive_n_set

bool QUICPlugin::quic_derive_secrets(uint8_t *secret)
{
   uint8_t *quic_key;
   uint8_t len_quic_key;

   uint8_t *quic_iv;
   uint8_t len_quic_iv;

   uint8_t *quic_hp;
   uint8_t len_quic_hp;


   // expand label for other initial secrets
   expand_label("tls13 ", "quic key", NULL, 0, 16, quic_key, len_quic_key);
   expand_label("tls13 ", "quic iv", NULL, 0, 12, quic_iv, len_quic_iv);
   expand_label("tls13 ", "quic hp", NULL, 0, 16, quic_hp, len_quic_hp);


   // use HKDF-Expand to derive other secrets
   if (!quic_derive_n_set(secret, quic_key, len_quic_key, AES_128_KEY_LENGTH, initial_secrets.key) ||
     !quic_derive_n_set(secret, quic_iv, len_quic_iv, TLS13_AEAD_NONCE_LENGTH, initial_secrets.iv) ||
     !quic_derive_n_set(secret, quic_hp, len_quic_hp, AES_128_KEY_LENGTH, initial_secrets.hp)){
      free(quic_key);
      free(quic_iv);
      free(quic_hp);
      DEBUG_MSG("Error, derivation of initial secrets failed");
      return false;
   }


   free(quic_key);
   free(quic_iv);
   free(quic_hp);
   return true;
} // QUICPlugin::quic_derive_secrets

uint8_t QUICPlugin::quic_draft_version(uint32_t version)
{
   if ((version >> 8) == 0xff0000){
      return (uint8_t) version;
   }

   switch (version){
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

bool QUICPlugin::quic_create_initial_secrets(const char *side)
{
   uint32_t version = quic_h1->version;

   version = htonl(version);

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

   if (version == 0x51303530)
      salt = hanshake_salt_draft_q50;
   else if (version == 0x54303530)
      salt = hanshake_salt_draft_t50;
   else if (version == 0x54303531)
      salt = hanshake_salt_draft_t51;
   else if (quic_check_version(version, 22))
      salt = handshake_salt_draft_22;
   else if (quic_check_version(version, 28))
      salt = handshake_salt_draft_23;
   else if (quic_check_version(version, 32))
      salt = handshake_salt_draft_29;
   else
      salt = handshake_salt_v1;


   uint8_t extracted_secret[HASH_SHA2_256_LENGTH] = { 0 };
   uint8_t expanded_secret[HASH_SHA2_256_LENGTH]  = { 0 };
   size_t expd_len = HASH_SHA2_256_LENGTH;
   size_t extr_len = HASH_SHA2_256_LENGTH;

   uint8_t *client_In_Buffer;
   uint8_t clien_In_Len;

   uint8_t *cid    = nullptr;
   uint8_t cid_len = 0;

   if (!strcmp(side, "client in")){
      cid     = dcid;
      cid_len = quic_h1->dcid_len;
   } else if (!strcmp(side, "server in")){
      cid     = scid;
      cid_len = quic_h2->scid_len;
   }


   // HKDF-Extract
   EVP_PKEY_CTX *pctx;

   pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
   if (!EVP_PKEY_derive_init(pctx)){
      DEBUG_MSG("Error, context initialization failed(Extract)");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)){
      DEBUG_MSG("Error, mode initialization failed(Extract)");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())){
      DEBUG_MSG("Error, message digest initialization failed(Extract)");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, SALT_LENGTH)){
      DEBUG_MSG("Error, salt initialization failed(Extract)");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, cid, cid_len)){
      DEBUG_MSG("Error, key initialization failed(Extract)");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_derive(pctx, extracted_secret, &extr_len)){
      DEBUG_MSG("Error, HKDF-Extract derivation failed");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }


   // Expand-Label
   expand_label("tls13 ", side, NULL, 0, HASH_SHA2_256_LENGTH, client_In_Buffer, clien_In_Len);

   // HKDF-Expand
   if (!EVP_PKEY_derive_init(pctx)){
      DEBUG_MSG("Error, context initialization failed(Expand)");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)){
      DEBUG_MSG("Error, mode initialization failed(Expand)");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())){
      DEBUG_MSG("Error, message digest initialization failed(Expand)");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx, client_In_Buffer, clien_In_Len)){
      DEBUG_MSG("Error, info initialization failed(Expand)");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, extracted_secret, HASH_SHA2_256_LENGTH)){
      DEBUG_MSG("Error, key initialization failed(Expand)");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   if (1 != EVP_PKEY_derive(pctx, expanded_secret, &expd_len)){
      DEBUG_MSG("Error, HKDF-Expand derivation failed");
      EVP_PKEY_CTX_free(pctx);
      return false;
   }
   EVP_PKEY_CTX_free(pctx);
   free(client_In_Buffer);


   // Derive other secrets
   if (!quic_derive_secrets(expanded_secret)){
      DEBUG_MSG("Error, Derivation of initial secrets failed");
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

   if (!(ctx = EVP_CIPHER_CTX_new())){
      DEBUG_MSG("Sample encryption, creating context failed");
      return false;
   }
   if (!(EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, initial_secrets.hp, NULL))){
      DEBUG_MSG("Sample encryption, context initialization failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }


   // set padding always returns 1 so no need for success
   // we need to disable padding so we can use EncryptFinal

   EVP_CIPHER_CTX_set_padding(ctx, 0);
   if (!(EVP_EncryptUpdate(ctx, plaintext, &len, sample, SAMPLE_LENGTH))){
      DEBUG_MSG("Sample encryption, decrypting header failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!(EVP_EncryptFinal_ex(ctx, plaintext + len, &len))){
      DEBUG_MSG("Sample encryption, final header decryption failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }

   EVP_CIPHER_CTX_free(ctx);
   memcpy(mask, plaintext, sizeof(mask));

   // https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-22#section-5.4.1

   //   if (packet[0] & 0x80) == 0x80:
   //      # Long header: 4 bits masked
   //      packet[0] ^= mask[0] & 0x0f
   //   else:
   //     # Short header: 5 bits masked
   //     packet[0] ^= mask[0] & 0x1f

   // we do not have to handle short header, Initial packets have only long header

   first_byte  = quic_h1->first_byte;
   first_byte ^= mask[0] & 0x0f;
   uint8_t pkn_len = (first_byte & 0x03) + 1;

   // set decrypted first byte
   header[0] = first_byte;


   // copy encrypted pkn into buffer
   memcpy(&full_pkn, pkn, pkn_len);


   // decrypt pkn
   for (unsigned int i = 0; i < pkn_len; i++){
      packet_number |= (full_pkn[i] ^ mask[1 + i]) << (8 * (pkn_len - 1 - i));
   }


   // after decrypting first byte, we know packet number length, so we can adjust payload start and lengths
   payload     = payload + pkn_len;
   payload_len = payload_len - pkn_len;
   header_len  = header_len + pkn_len;

   // set decrypted packet number
   for (unsigned i = 0; i < pkn_len; i++){
      header[header_len - 1 - i] = (uint8_t) (packet_number >> (8 * i));
   }


   // adjust nonce for payload decryption
   phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ packet_number);

   return true;
} // QUICPlugin::quic_decrypt_header

void QUICPlugin::phton64(uint8_t *p, uint64_t v)
{
   int shift = 56;

   for (unsigned int i = 0; i < 8; i++){
      p[i] = (uint8_t) (v >> (shift - (i * 8)));
   }
}

uint64_t QUICPlugin::pntoh64(const void *p)
{
   uint64_t buffer = 0;
   int shift       = 56;

   for (unsigned x = 0; x < 8; x++){
      buffer |= (uint64_t) *((const uint8_t *) (p) + x) << (shift - (x * 8));
   }
   return buffer;
}

bool QUICPlugin::quic_decrypt_payload()
{
   uint8_t atag[16] = { 0 };
   int len;


   /* Input is --> "header || ciphertext (buffer) || auth tag (16 bytes)" */

   if (payload_len <= 16){
      DEBUG_MSG("Payload decryption error, ciphertext too short");
      return false;
   }

   // https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-34#section-5.3
   // "These cipher suites have a 16-byte authentication tag and produce an output 16 bytes larger than their input."

   // adjust length because last 16 bytes are authentication tag
   payload_len -= 16;
   // set tag based on last 16 bytes
   memcpy(&atag, &payload[payload_len], 16);


   EVP_CIPHER_CTX *ctx;

   // +16 means we have to allocate space for authentication tag
   decrypted_payload = (uint8_t *) malloc(sizeof(uint8_t) * payload_len + 16);

   if (!(ctx = EVP_CIPHER_CTX_new())){
      DEBUG_MSG("Payload decryption error, creating context failed");
      return false;
   }
   if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)){
      DEBUG_MSG("Payload decryption error, context initialization failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TLS13_AEAD_NONCE_LENGTH, NULL)){
      DEBUG_MSG("Payload decryption error, setting NONCE length failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, atag)){
      DEBUG_MSG("Payload decryption error, TAG check failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!EVP_DecryptInit_ex(ctx, NULL, NULL, initial_secrets.key, nonce)){
      DEBUG_MSG("Payload decryption error, setting KEY and NONCE failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!EVP_DecryptUpdate(ctx, NULL, &len, header, header_len)){
      DEBUG_MSG("Payload decryption error, initializing authenticated data failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!EVP_DecryptUpdate(ctx, decrypted_payload, &len, payload, payload_len)){
      DEBUG_MSG("Payload decryption error, decrypting payload failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }
   if (!EVP_DecryptFinal_ex(ctx, decrypted_payload + len, &len)){
      DEBUG_MSG("Payload decryption error, final payload decryption failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
   }

   EVP_CIPHER_CTX_free(ctx);
   return true;
} // QUICPlugin::quic_decrypt_payload

bool QUICPlugin::quic_check_initial(uint8_t packet0)
{
   // check if packet has LONG HEADER form.
   if ((packet0 & 0x80) == 0x80){
      // check if packet is type INITIAL.
      if ((packet0 & 0x30) == 0x00){
         return true;
      } else {
         return false;
      }
   } else {
      return false;
   }
}

void QUICPlugin::quic_parse_data(const Packet &pkt)
{
   uint8_t *tmp_pointer = (uint8_t *) pkt.payload;
   header = (uint8_t *) tmp_pointer; // set header pointer

   quic_h1 = (quic_header1 *) tmp_pointer; // read first byte, version and dcid length

   tmp_pointer += sizeof(quic_header1); // move after first struct

   if (quic_h1->dcid_len != 0){
      dcid = tmp_pointer;  // set dcid if dcid length is not 0
   }
   tmp_pointer += quic_h1->dcid_len; // move after dcid

   quic_h2 = (quic_header2 *) tmp_pointer; // read scid length

   tmp_pointer += sizeof(quic_header2); // move after scid length

   if (quic_h2->scid_len != 0){ // set scid if scid length is not 0
      scid = tmp_pointer;
   }
   tmp_pointer += quic_h2->scid_len;


   quic_h3 = (quic_header3 *) tmp_pointer; // read overall length this length consists of packet number length and payload length

   tmp_pointer += sizeof(quic_header3);
   tmp_pointer += quic_h3->token_len;


   quic_h4      = (quic_header4 *) tmp_pointer;
   tmp_pointer += sizeof(uint16_t); // move after length, there should be packet number

   pkn = tmp_pointer; // set packet number

   payload = tmp_pointer; // set payload start too, this pointer is adjusted later, because we do not know exact packet number length atm

   tmp_pointer += sizeof(uint8_t) * 4; // skip packet number and go to sample start which is always after packet number(always assuming length of packet number == 4).

   sample = tmp_pointer; // set sample pointer

   if (tmp_pointer > payload_end) {
      return false;
   }

   payload_len = htons(quic_h4->length) ^ 0x4000; // set payload length, again, payload length is with payload_len + pkn_len , this will be adjusted later.

   header_len = pkt.payload_length - payload_len; // set header_length, will be adjusted later
   return true;
} // QUICPlugin::quic_parse_data

void QUICPlugin::quic_clean()
{
   free(decrypted_payload);
   decrypted_payload = nullptr;
}

bool QUICPlugin::process_quic(RecordExtQUIC *quic_data, const Packet &pkt)
{
   // check if packet contains LONG HEADER and is of type INITIAL
   if (!quic_check_initial(pkt.payload[0])){
      DEBUG_MSG("Packet is not Initial or does not contains LONG HEADER");
      return false;
   }


   // header data extraction can extract data for both sides (client and server side), the differece is that server side header contains SCID length and so SCID.
   quic_parse_data(pkt);
   // DONT check direction, CRYPTO frame is always contained in Client Hello packet,
   // but let choose side ("client in" / "server in") for future expansion
   if (!quic_create_initial_secrets("client in")){
      DEBUG_MSG("Error, creation of initial secrets failed (client side)");
      return false;
   }
   if (!quic_decrypt_header()){
      DEBUG_MSG("Error, header decryption failed (client side)");
      return false;
   }
   if (!quic_decrypt_payload()){
      DEBUG_MSG("Error, payload decryption failed (client side)");
      quic_clean();
      return false;
   }
   if (!parse_tls(quic_data)){
      DEBUG_MSG("SNI Extraction failed");
      quic_clean();
      return false;
   } else {
      quic_clean();
      return true;
   }
} // QUICPlugin::process_quic

int QUICPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int QUICPlugin::post_create(Flow &rec, const Packet &pkt)
{
   /*RecordExtQUIC * quic_ptr = new RecordExtQUIC();
    * rec.addExtension(quic_ptr);
    * process_quic(quic_ptr,pkt);
    * return 0;*/


   if (quic_ptr == nullptr){
      quic_ptr = new RecordExtQUIC();
   }

   if (process_quic(quic_ptr, pkt)){
      rec.addExtension(quic_ptr);
      quic_ptr = nullptr;
   }
   return 0;
}

int QUICPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int QUICPlugin::post_update(Flow &rec, const Packet &pkt)
{
   RecordExtQUIC *quic_ptr = (RecordExtQUIC *) rec.getExtension(quic);

   process_quic(quic_ptr, pkt);
   return 0;
}

void QUICPlugin::finish()
{
   if (print_stats){
      // DEBUG_MSG("QUIC plugin stats:" );
      cout << "TLS plugin stats:" << endl;
      cout << "   Parsed SNI: " << parsed_initial << endl;
   }
}

const char *ipfix_quic_template[] = {
   IPFIX_QUIC_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **QUICPlugin::get_ipfix_string()
{
   return ipfix_quic_template;
}

string QUICPlugin::get_unirec_field_string()
{
   return QUIC_UNIREC_TEMPLATE;
}
