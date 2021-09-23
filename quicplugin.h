/**
 * \file quicplugin.h
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

#ifndef QUICPLUGIN_H
#define QUICPLUGIN_H

#include <string>

#ifdef WITH_NEMEA
# include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "tlsplugin.h"


using namespace std;


#define HASH_SHA2_256_LENGTH    32
#define TLS13_AEAD_NONCE_LENGTH 12
#define AES_128_KEY_LENGTH      16
#define CRYPTO_FRAME            06
#define CLIENT_HELLO            1
#define SAMPLE_LENGTH           16
#define SALT_LENGTH             20

struct my_payload_data {
   uint8_t *data;
   uint8_t *end;
   bool     valid;
   int      sni_parsed;
};


typedef struct __attribute__((packed)) quic_header1 {
   uint8_t  first_byte;
   uint32_t version;
   uint8_t  dcid_len;
   // contains first byte , version and dcid length which have always static size
} quic_header1;


typedef struct __attribute__((packed)) quic_header2 {
   uint8_t scid_len;
   // contains scid_len (which is 0 in context of Client Hello packet) but from server side, header contains SCID so SCID length is not 0
} quic_header2;

typedef struct __attribute__((packed)) quic_header3 {
   uint8_t token_len;
   // token_len (variable) but not important
} quic_header3;

typedef struct __attribute__((packed)) quic_header4 {
   uint16_t length;
   // contains length (which consist of payload length + packet number length)
} quic_header4;

struct __attribute__((packed)) tls_handshake_prot {
   uint8_t     type;
   uint8_t     length1; // length field is 3 bytes long...
   uint16_t    length2;
   tls_version version;
};

struct __attribute__((packed)) tls_rec_lay {
   uint8_t  type;
   uint8_t  offset;
   uint16_t length;
};

typedef struct Initial_Secrets {
   uint8_t key[AES_128_KEY_LENGTH];
   uint8_t iv[TLS13_AEAD_NONCE_LENGTH];
   uint8_t hp[AES_128_KEY_LENGTH];
} Initial_Secrets;


/**
 * \brief Flow record extension header for storing parsed QUIC packets.
 */
struct RecordExtQUIC : RecordExt {
   int  sni_count = 0;
   char sni[255]  = { 0 };
   RecordExtQUIC() : RecordExt(quic)
   {
      sni[0] = 0;
   }

   #ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_QUIC_SNI, sni);
   }

   #endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int len = strlen(sni);
      int pos = 0;

      if (len + 2 > size){
         return -1;
      }

      buffer[pos++] = len;
      memcpy(buffer + pos, sni, len);
      pos += len;

      return pos;
   }
};

/**
 * \brief Flow cache plugin for parsing QUIC packets.
 */
class QUICPlugin : public FlowCachePlugin
{
public:
   QUICPlugin(const options_t &module_options);
   QUICPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   ~QUICPlugin();
   FlowCachePlugin *copy();
   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();

private:
   bool print_stats; /**< Print stats when flow cache finish. */
   bool     process_quic(RecordExtQUIC *, const Packet&);


   bool     quic_check_initial(uint8_t);
   void     quic_parse_data(const Packet&);
   bool     quic_create_initial_secrets(const char *);
   bool     quic_check_version(uint32_t, uint8_t);
   uint8_t  quic_draft_version(uint32_t);

   bool     quic_decrypt_header();
   bool     quic_decrypt_payload();

   bool     quic_derive_secrets(uint8_t *);
   bool     quic_derive_n_set(uint8_t *, uint8_t *, uint8_t, size_t, uint8_t *);
   bool     expand_label(const char *, const char *, const uint8_t *, uint8_t, uint16_t, uint8_t *&, uint8_t &);
   bool     parse_tls(RecordExtQUIC *);
   void     get_tls_server_name(my_payload_data&, RecordExtQUIC *);
   void     get_ja3_cipher_suites(stringstream&, my_payload_data&);
   bool     is_grease_value(uint16_t);
   void     quic_clean();


   uint64_t pntoh64(const void *);
   void     phton64(uint8_t *, uint64_t);

   // header pointers
   quic_header1 *quic_h1;
   quic_header2 *quic_h2;
   quic_header3 *quic_h3;
   quic_header4 *quic_h4;


   // important pointers into QUIC packet, used in decryption process

   uint8_t *header;
   uint8_t *payload;

   uint16_t header_len;
   uint16_t payload_len;

   // important header values (sample is part of payload)
   uint8_t *dcid;
   uint8_t *scid;
   uint8_t *pkn;
   uint8_t *sample;

   // final decrypted payload
   uint8_t *decrypted_payload;
   int plaintext_len;

   uint8_t nonce[TLS13_AEAD_NONCE_LENGTH] = { 0 };

   // counter
   int parsed_initial;

   RecordExtQUIC *quic_ptr;

   Initial_Secrets initial_secrets;
};

#endif // ifndef QUICPLUGIN_H
