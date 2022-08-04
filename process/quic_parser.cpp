/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, CESNET z.s.p.o.
 */

/**
 * \file quic_parser.cpp
 * \brief Class for parsing quic traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \date 2022
 */


#include "quic_parser.hpp"

// #include "quic_variable_length.cpp"

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

namespace ipxp {
QUICParser::QUICParser()
{
   quic_h1 = nullptr;
   quic_h2 = nullptr;
   payload = nullptr;

   header_len  = 0;
   payload_len = 0;

   dcid           = nullptr;
   pkn            = nullptr;
   sample         = nullptr;
   salt           = nullptr;
   final_payload  = nullptr;
   parsed_initial = 0;
   is_version2    = false;
}

void QUICParser::quic_get_version(uint32_t& version_toset)
{
   version_toset = version;
   return;
}

void QUICParser::quic_get_sni(char *in)
{
   memcpy(in, sni, BUFF_SIZE);
   return;
}

void QUICParser::quic_get_user_agent(char *in)
{
   memcpy(in, user_agent, BUFF_SIZE);
   return;
}

bool QUICParser::quic_check_pointer_pos(const uint8_t *current, const uint8_t *end)
{
   if (current < end)
      return true;

   return false;
}

uint64_t QUICParser::quic_get_variable_length(const uint8_t *start, uint64_t &offset)
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
} // QUICParser::quic_get_variable_length

bool QUICParser::quic_obtain_tls_data(TLSData &payload)
{
   while (payload.start + sizeof(tls_ext) <= payload.end) {
      tls_ext *ext    = (tls_ext *) payload.start;
      uint16_t type   = ntohs(ext->type);
      uint16_t length = ntohs(ext->length);

      payload.start += sizeof(tls_ext);

      if (payload.start + length > payload.end) {
         break;
      }

      if (type == TLS_EXT_SERVER_NAME && length != 0) {
         tls_parser.tls_get_server_name(payload, sni, BUFF_SIZE);
      } else if ((type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1 
         || type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS 
         || type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V2) 
         && length != 0) {
         tls_parser.tls_get_quic_user_agent(payload, user_agent, BUFF_SIZE);
      }
      payload.start += length;
   }
   return payload.obejcts_parsed != 0;
}

bool QUICParser::quic_parse_tls()
{
   TLSData payload = {
      payload.start = final_payload + quic_crypto_start,
      payload.end   = final_payload + quic_crypto_start + quic_crypto_len,
      payload.obejcts_parsed = 0,
   };

   if (!tls_parser.tls_check_handshake(payload)) {
      return false;
   }
   if (!tls_parser.tls_skip_random(payload)) {
      return false;
   }
   if (!tls_parser.tls_skip_sessid(payload)) {
      return false;
   }
   if (!tls_parser.tls_skip_cipher_suites(payload)) {
      return false;
   }
   if (!tls_parser.tls_skip_compression_met(payload)) {
      return false;
   }
   if (!tls_parser.tls_check_ext_len(payload)) {
      return false;
   }
   if (!quic_obtain_tls_data(payload)) {
      return false;
   }
   return true;
} // QUICPlugin::quic_parse_tls

uint8_t QUICParser::quic_draft_version(uint32_t version)
{
   // this is IETF implementation, older version used
   if ((version >> 8) == older_version) {
      return (uint8_t) version;
   }
   switch (version) {
   // older mvfst version, but still used, based on draft 22, but salt 21 used
   case (faceebook1):
      return 22;
   // more used atm, salt 23 used
   case faceebook2:
   case facebook_experimental:
      return 27;
   case (force_ver_neg_pattern & 0x0F0F0F0F):
      return 29;

   // version 2 draft 00
   case q_version2_draft00:
   // newest
   case q_version2_newest:
      return 100;

   default:
      return 255;
   }
}

bool QUICParser::quic_check_version(uint32_t version, uint8_t max_version)
{
   uint8_t draft_version = quic_draft_version(version);

   return draft_version && draft_version <= max_version;
}

bool QUICParser::quic_obtain_version()
{
   version = quic_h1->version;
   version = ntohl(version);
   // this salt is used to draft 7-9
   static const uint8_t handshake_salt_draft_7[SALT_LENGTH] =
   {
      0xaf, 0xc8, 0x24, 0xec, 0x5f, 0xc7, 0x7e, 0xca, 0x1e, 0x9d,
      0x36, 0xf3, 0x7f, 0xb2, 0xd4, 0x65, 0x18, 0xc3, 0x66, 0x39
   };
   // this salt is used to draft 10-16
   static const uint8_t handshake_salt_draft_10[SALT_LENGTH] =
   {
      0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96,
      0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38
   };
   // this salt is used to draft 17-20
   static const uint8_t handshake_salt_draft_17[SALT_LENGTH] =
   {
      0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef,
      0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0
   };
   // this salt is used to draft 21-22
   static const uint8_t handshake_salt_draft_21[SALT_LENGTH] =
   {
      0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
      0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a
   };
   // this salt is used to draft 23-28
   static const uint8_t handshake_salt_draft_23[SALT_LENGTH] =
   {
      0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
      0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
   };
   // this salt is used to draft 29-32
   static const uint8_t handshake_salt_draft_29[SALT_LENGTH] =
   {
      0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
      0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
   };
   // newest 33 -
   static const uint8_t handshake_salt_v1[SALT_LENGTH] =
   {
      0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
      0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
   };
   static const uint8_t handshake_salt_v2[SALT_LENGTH] =
   {
      0xa7, 0x07, 0xc2, 0x03, 0xa5, 0x9b, 0x47, 0x18, 0x4a, 0x1d,
      0x62, 0xca, 0x57, 0x04, 0x06, 0xea, 0x7a, 0xe3, 0xe5, 0xd3
   };

   if (version == version_negotiation) {
      DEBUG_MSG("Error, version negotiation\n");
      return false;
   } else if (!is_version2 && version == quic_newest) {
      salt = handshake_salt_v1;
   } else if (!is_version2 && quic_check_version(version, 9)) {
      salt = handshake_salt_draft_7;
   } else if (!is_version2 && quic_check_version(version, 16)) {
      salt = handshake_salt_draft_10;
   } else if (!is_version2 && quic_check_version(version, 20)) {
      salt = handshake_salt_draft_17;
   } else if (!is_version2 && quic_check_version(version, 22)) {
      salt = handshake_salt_draft_21;
   } else if (!is_version2 && quic_check_version(version, 28)) {
      salt = handshake_salt_draft_23;
   } else if (!is_version2 && quic_check_version(version, 32)) {
      salt = handshake_salt_draft_29;
   } else if (is_version2 && quic_check_version(version, 100)) {
      salt = handshake_salt_v2;
   } else {
      DEBUG_MSG("Error, version not supported\n");
      return false;
   }

   return true;
} // QUICParser::quic_obtain_version

bool expand_label(const char *label_prefix, const char *label, const uint8_t *context_hash,
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

bool quic_derive_n_set(uint8_t *secret, uint8_t *expanded_label, uint8_t size, size_t output_len,
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

bool QUICParser::quic_derive_secrets(uint8_t *secret)
{
   uint8_t len_quic_key;
   uint8_t len_quic_iv;
   uint8_t len_quic_hp;

   // expand label for other initial secrets
   if (!is_version2) {
      uint8_t quic_key[quic_key_hkdf_v1] = { 0 };
      uint8_t quic_iv[quic_iv_hkdf_v1]   = { 0 };
      uint8_t quic_hp[quic_hp_hkdf_v1]   = { 0 };
      expand_label("tls13 ", "quic key", NULL, 0, AES_128_KEY_LENGTH, quic_key, len_quic_key);
      expand_label("tls13 ", "quic iv", NULL, 0, TLS13_AEAD_NONCE_LENGTH, quic_iv, len_quic_iv);
      expand_label("tls13 ", "quic hp", NULL, 0, AES_128_KEY_LENGTH, quic_hp, len_quic_hp);
      // use HKDF-Expand to derive other secrets
      if (!quic_derive_n_set(secret, quic_key, len_quic_key, AES_128_KEY_LENGTH, initial_secrets.key) ||
        !quic_derive_n_set(secret, quic_iv, len_quic_iv, TLS13_AEAD_NONCE_LENGTH, initial_secrets.iv) ||
        !quic_derive_n_set(secret, quic_hp, len_quic_hp, AES_128_KEY_LENGTH, initial_secrets.hp)) {
         DEBUG_MSG("Error, derivation of initial secrets failed\n");
         return false;
      }
   } else {
      uint8_t quic_key[quic_key_hkdf_v2] = { 0 };
      uint8_t quic_iv[quic_iv_hkdf_v2]   = { 0 };
      uint8_t quic_hp[quic_hp_hkdf_v2]   = { 0 };
      expand_label("tls13 ", "quicv2 key", NULL, 0, AES_128_KEY_LENGTH, quic_key, len_quic_key);
      expand_label("tls13 ", "quicv2 iv", NULL, 0, TLS13_AEAD_NONCE_LENGTH, quic_iv, len_quic_iv);
      expand_label("tls13 ", "quicv2 hp", NULL, 0, AES_128_KEY_LENGTH, quic_hp, len_quic_hp);

      // use HKDF-Expand to derive other secrets
      if (!quic_derive_n_set(secret, quic_key, len_quic_key, AES_128_KEY_LENGTH, initial_secrets.key) ||
        !quic_derive_n_set(secret, quic_iv, len_quic_iv, TLS13_AEAD_NONCE_LENGTH, initial_secrets.iv) ||
        !quic_derive_n_set(secret, quic_hp, len_quic_hp, AES_128_KEY_LENGTH, initial_secrets.hp)) {
         DEBUG_MSG("Error, derivation of initial secrets failed\n");
         return false;
      }
   }

   return true;
} // QUICPlugin::quic_derive_secrets

bool QUICParser::quic_create_initial_secrets()
{
   uint8_t extracted_secret[HASH_SHA2_256_LENGTH] = { 0 };
   size_t extr_len = HASH_SHA2_256_LENGTH;


   uint8_t expanded_secret[HASH_SHA2_256_LENGTH] = { 0 };
   size_t expd_len = HASH_SHA2_256_LENGTH;


   uint8_t expand_label_buffer[quic_clientin_hkdf];
   uint8_t expand_label_len;


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
   if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, dcid, quic_h1->dcid_len)) {
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
   expand_label("tls13 ", "client in", NULL, 0, HASH_SHA2_256_LENGTH, expand_label_buffer, expand_label_len);
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
   if (!quic_derive_secrets(expanded_secret)) {
      DEBUG_MSG("Error, Derivation of initial secrets failed\n");
      return false;
   }
   return true;
} // QUICPlugin::quic_create_initial_secrets

bool QUICParser::quic_encrypt_sample(uint8_t *plaintext)
{
   int len = 0;
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
   return true;
}

bool QUICParser::quic_decrypt_header(const Packet & pkt)
{
   uint8_t plaintext[SAMPLE_LENGTH];
   uint8_t mask[5]        = { 0 };
   uint8_t full_pkn[4]    = { 0 };
   uint8_t first_byte     = 0;
   uint32_t packet_number = 0;
   uint8_t pkn_len;

   // https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection-applicati

   /*
    * mask = header_protection(hp_key, sample)
    *
    * pn_length = (packet[0] & 0x03) + 1
    *
    * if (packet[0] & 0x80) == 0x80:
    # Long header: 4 bits masked
    #    packet[0] ^= mask[0] & 0x0f
    # else:
    # Short header: 5 bits masked
    #    packet[0] ^= mask[0] & 0x1f
    */

   // Encrypt sample with AES-ECB. Encrypted sample is used in XOR with packet header
   if (!quic_encrypt_sample(plaintext)) {
      return false;
   }
   memcpy(mask, plaintext, sizeof(mask));

   first_byte = quic_h1->first_byte ^ (mask[0] & 0x0f);
   pkn_len    = (first_byte & 0x03) + 1;

   // after de-obfuscating pkn, we know exactly pkn length so we can correctly adjust start of payload
   payload     = payload + pkn_len;
   payload_len = payload_len - pkn_len;
   header_len  = payload - pkt.payload;
   if (header_len > MAX_HEADER_LEN) {
      DEBUG_MSG("Header length too long\n");
      return false;
   }

   memcpy(tmp_header_mem, pkt.payload, header_len);
   header = tmp_header_mem;

   header[0] = first_byte;

   memcpy(&full_pkn, pkn, pkn_len);
   for (unsigned int i = 0; i < pkn_len; i++) {
      packet_number |= (full_pkn[i] ^ mask[1 + i]) << (8 * (pkn_len - 1 - i));
   }
   for (unsigned i = 0; i < pkn_len; i++) {
      header[header_len - 1 - i] = (uint8_t) (packet_number >> (8 * i));
   }
   // adjust nonce for payload decryption
   // https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
   //  The exclusive OR of the padded packet number and the IV forms the AEAD nonce
   phton64(initial_secrets.iv + sizeof(initial_secrets.iv) - 8,
     pntoh64(initial_secrets.iv + sizeof(initial_secrets.iv) - 8) ^ packet_number);
   return true;
} // QUICPlugin::quic_decrypt_header

bool QUICParser::quic_decrypt_payload()
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
   if (!EVP_DecryptInit_ex(ctx, NULL, NULL, initial_secrets.key, initial_secrets.iv)) {
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

bool QUICParser::quic_check_frame_type(uint8_t *where, FRAME_TYPE frame_type)
{
   return (*where) == frame_type;
}

inline void QUICParser::quic_skip_ack1(uint8_t *start, uint64_t &offset)
{
   // https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
   offset++;
   quic_get_variable_length(start, offset);
   quic_get_variable_length(start, offset);
   uint64_t quic_ack_range_count = quic_get_variable_length(start, offset);

   quic_get_variable_length(start, offset);

   for (uint64_t x = 0; x < quic_ack_range_count; x++) {
      quic_get_variable_length(start, offset);
      quic_get_variable_length(start, offset);
   }
   return;
}

inline void QUICParser::quic_skip_ack2(uint8_t *start, uint64_t &offset)
{
   // https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
   offset++;
   quic_get_variable_length(start, offset);
   quic_get_variable_length(start, offset);
   uint64_t quic_ack_range_count = quic_get_variable_length(start, offset);

   quic_get_variable_length(start, offset);

   for (uint64_t x = 0; x < quic_ack_range_count; x++) {
      quic_get_variable_length(start, offset);
      quic_get_variable_length(start, offset);
   }
   quic_get_variable_length(start, offset);
   quic_get_variable_length(start, offset);
   quic_get_variable_length(start, offset);
   return;
}

inline void QUICParser::quic_skip_connection_close1(uint8_t *start, uint64_t &offset)
{
   // https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
   offset++;
   quic_get_variable_length(start, offset);
   quic_get_variable_length(start, offset);
   uint64_t reason_phrase_length = quic_get_variable_length(start, offset);

   offset += reason_phrase_length;
   return;
}

inline void QUICParser::quic_skip_connection_close2(uint8_t *start, uint64_t &offset)
{
   // https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
   offset++;
   quic_get_variable_length(start, offset);
   uint64_t reason_phrase_length = quic_get_variable_length(start, offset);

   offset += reason_phrase_length;
   return;
}

inline void QUICParser::quic_copy_crypto(uint8_t *start, uint64_t &offset)
{
   offset += 1;
   uint16_t frame_offset = quic_get_variable_length(start, offset);
   uint16_t frame_length = quic_get_variable_length(start, offset);

   memcpy(assembled_payload + frame_offset, start + offset, frame_length);
   if (frame_offset < quic_crypto_start) {
      quic_crypto_start = frame_offset;
   }
   quic_crypto_len += frame_length;
   offset += frame_length;
   return;
}

bool QUICParser::quic_reassemble_frames()
{
   quic_crypto_start = UINT16_MAX;
   quic_crypto_len   = 0;

   uint64_t offset      = 0;
   uint8_t *payload_end = decrypted_payload + payload_len;
   uint8_t *current     = decrypted_payload + offset;

   while (quic_check_pointer_pos(current, payload_end)) {
      // https://www.rfc-editor.org/rfc/rfc9000.html#name-frames-and-frame-types
      // only those frames can occure in initial packets
      if (quic_check_frame_type(current, CRYPTO)) {
         quic_copy_crypto(decrypted_payload, offset);
      } else if (quic_check_frame_type(current, ACK1)) {
         quic_skip_ack1(decrypted_payload, offset);
      } else if (quic_check_frame_type(current, ACK2)) {
         quic_skip_ack1(decrypted_payload, offset);
      } else if (quic_check_frame_type(current, CONNECTION_CLOSE1)) {
         quic_skip_connection_close1(decrypted_payload, offset);
      } else if (quic_check_frame_type(current, CONNECTION_CLOSE2)) {
         quic_skip_connection_close2(decrypted_payload, offset);
      } else if (quic_check_frame_type(current, PADDING) ||
        quic_check_frame_type(current, PING)) {
         offset++;
      } else {
         DEBUG_MSG("Wrong Frame type read during frames assemble\n");
         return false;
      }
      current = decrypted_payload + offset;
   }

   if (quic_crypto_start == UINT16_MAX)
      return false;

   final_payload = assembled_payload;
   return true;
} // QUICParser::quic_reassemble_frames

void QUICParser::quic_initialze_arrays()
{
   // buffer for decrypted payload
   memset(decrypted_payload, 0, CURRENT_BUFFER_SIZE);
   // buffer for reassembled payload
   memset(assembled_payload, 0, CURRENT_BUFFER_SIZE);
   // buffer for quic header
   memset(tmp_header_mem, 0, MAX_HEADER_LEN);
}

bool QUICParser::quic_check_initial(uint8_t packet0)
{
   // version 1 (header form:long header(1) | fixed bit:fixed(1) | long packet type:initial(00) --> 1100 --> C)
   if ((packet0 & 0xF0) == 0xC0) {
      is_version2 = false;
      return true;
   }
   // version 2 (header form:long header(1) | fixed bit:fixed(1) | long packet type:initial(01) --> 1101 --> D)
   else if ((packet0 & 0xF0) == 0xD0) {
      is_version2 = true;
      return true;
   } else {
      return false;
   }
}

bool QUICParser::quic_initial_checks(const Packet&pkt)
{
   // Port check, Initial packet check and UDP check
   if (pkt.ip_proto != 17 || !quic_check_initial(pkt.payload[0]) || pkt.dst_port != 443) {
      DEBUG_MSG("Packet is not Initial or does not contains LONG HEADER or is not on port 443\n");
      return false;
   }
   return true;
}

bool QUICParser::quic_parse_header(const Packet & pkt)
{
   const uint8_t *payload_pointer = pkt.payload;
   uint64_t offset = 0;

   const uint8_t *payload_end = payload_pointer + pkt.payload_len;

   quic_h1 = (quic_first_ver_dcidlen *) (payload_pointer + offset);

   if (!quic_obtain_version()) {
      DEBUG_MSG("Error, version not supported\n");
      return false;
   }

   offset += sizeof(quic_first_ver_dcidlen);

   if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
      return false;
   }


   if (quic_h1->dcid_len != 0) {
      dcid    = (payload_pointer + offset);
      offset += quic_h1->dcid_len;
   }

   if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
      return false;
   }

   quic_h2 = (quic_scidlen *) (payload_pointer + offset);

   offset += sizeof(quic_scidlen);

   if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
      return false;
   }


   if (quic_h2->scid_len != 0) {
      offset += quic_h2->scid_len;
   }

   if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
      return false;
   }

   uint64_t token_length = quic_get_variable_length(payload_pointer, offset);

   if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
      return false;
   }

   offset += token_length;

   if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
      return false;
   }


   payload_len = quic_get_variable_length(payload_pointer, offset);
   if (payload_len > CURRENT_BUFFER_SIZE) {
      return false;
   }

   if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
      return false;
   }

   pkn = (payload_pointer + offset);

   payload = (payload_pointer + offset);

   offset += sizeof(uint8_t) * 4;
   sample  = (payload_pointer + offset);

   if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
      return false;
   }

   return true;
} // QUICPlugin::quic_parse_data

bool QUICParser::quic_start(const Packet& pkt)
{
   if (!quic_initial_checks(pkt)) {
      return false;
   }

   quic_initialze_arrays();
   if (!quic_parse_header(pkt)) {
      DEBUG_MSG("Error, parsing header failed\n");
      return false;
   }
   if (!quic_create_initial_secrets()) {
      DEBUG_MSG("Error, creation of initial secrets failed (client side)\n");
      return false;
   }
   if (!quic_decrypt_header(pkt)) {
      DEBUG_MSG("Error, header decryption failed (client side)\n");
      return false;
   }
   if (!quic_decrypt_payload()) {
      DEBUG_MSG("Error, payload decryption failed (client side)\n");
      return false;
   }
   if (!quic_reassemble_frames()) {
      DEBUG_MSG("Error, reassembling of crypto frames failed (client side)\n");
      return false;
   }
   if (!quic_parse_tls()) {
      DEBUG_MSG("SNI and User Agent Extraction failed\n");
      return false;
   }
   return true;
}
}
