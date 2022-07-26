/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, CESNET z.s.p.o.
 */

/**
 * \file quic_parser.hpp
 * \brief Class for parsing quic traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \date 2022
 */


#include <ipfixprobe/process.hpp>
#include <ipfixprobe/byte-utils.hpp>
#include "tls_parser.hpp"
#include <openssl/kdf.h>
#include <openssl/evp.h>


#define HASH_SHA2_256_LENGTH                 32
#define TLS13_AEAD_NONCE_LENGTH              12
#define SAMPLE_LENGTH                        16
#define SALT_LENGTH                          20
#define AES_128_KEY_LENGTH                   16

#define TLS_EXT_SERVER_NAME                  0
#define TLS_EXT_ALPN                         16
// draf-33, draft-34 a rfc9001, have this value defined as 0x39 == 57
#define TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1 0x39
// draf-13 az draft-32 have this value defined as 0xffa5 == 65445
#define TLS_EXT_QUIC_TRANSPORT_PARAMETERS    0xffa5
// draf-02 az draft-12 have this value defined as 0x26 == 38
#define TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V2 0x26
#define TLS_EXT_GOOGLE_USER_AGENT            0x3129


// first byte (1) + version (4) + dcid length (1) + dcid (20) + scid length (1) + scid (20) +
// token length (variable so max is 8) + token (idk) + length (max 8) + pkt number (4)
// cant figure out if token length has any boundaries, teoretically 8 byte version of token length
// means 2^64 as max length
// 67 (header basic data) + 100 (max token length)
#define MAX_HEADER_LEN      67 + 100
#define BUFF_SIZE           255
#define CURRENT_BUFFER_SIZE 1500

namespace ipxp {
typedef struct __attribute__((packed)) quic_first_ver_dcidlen {
   uint8_t  first_byte;
   uint32_t version;
   uint8_t  dcid_len;
} quic_first_ver_dcidlen;


typedef struct __attribute__((packed)) quic_scidlen {
   uint8_t scid_len;
} quic_scidlen;

typedef struct Initial_Secrets {
   uint8_t key[AES_128_KEY_LENGTH];
   uint8_t iv[TLS13_AEAD_NONCE_LENGTH];
   uint8_t hp[AES_128_KEY_LENGTH];
} Initial_Secrets;

class QUICParser
{
private:
   enum FRAME_TYPE {
      CRYPTO            = 0x06,
      PADDING           = 0x00,
      PING              = 0x01,
      ACK1              = 0x02,
      ACK2              = 0x03,
      CONNECTION_CLOSE1 = 0x1C,
      CONNECTION_CLOSE2 = 0x1D
   };
   enum HKDF_LENGTHS {
      quic_key_hkdf_v1   = sizeof("tls13 quic key") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
      quic_iv_hkdf_v1    = sizeof("tls13 quic iv") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
      quic_hp_hkdf_v1    = sizeof("tls13 quic hp") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
      quic_key_hkdf_v2   = sizeof("tls13 quicv2 key") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
      quic_iv_hkdf_v2    = sizeof("tls13 quicv2 iv") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
      quic_hp_hkdf_v2    = sizeof("tls13 quicv2 hp") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
      quic_clientin_hkdf = sizeof("tls13 client in") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t)
   };

   enum QUIC_VERSION {
      older_version         = 0xff0000,
      faceebook1            = 0xfaceb001,
      faceebook2            = 0xfaceb002,
      facebook_experimental = 0xfaceb00e,
      q_version2_draft00    = 0xff020000,
      q_version2_newest     = 0x709a50c4,
      force_ver_neg_pattern = 0x0a0a0a0a,
      version_negotiation   = 0x00000000,
      quic_newest           = 0x00000001
   };
   bool     quic_initial_checks(const Packet&);
   void     quic_initialze_arrays();
   bool     quic_check_initial(uint8_t);
   bool     quic_parse_header(const Packet&);
   bool     quic_create_initial_secrets();
   bool     quic_decrypt_header(const Packet & );
   bool     quic_decrypt_payload();
   bool     quic_reassemble_frames();
   bool     quic_parse_tls();
   bool     quic_obtain_version();
   bool     quic_derive_secrets(uint8_t *);
   bool     quic_check_frame_type(uint8_t *, FRAME_TYPE);
   void     quic_skip_ack1(uint8_t *, uint64_t&);
   void     quic_skip_ack2(uint8_t *, uint64_t&);
   void     quic_skip_connection_close1(uint8_t *, uint64_t&);
   void     quic_skip_connection_close2(uint8_t *, uint64_t&);
   void     quic_copy_crypto(uint8_t *, uint64_t&);
   bool     quic_encrypt_sample(uint8_t *);
   uint8_t  quic_draft_version(uint32_t);
   uint64_t quic_get_variable_length(const uint8_t *, uint64_t&);
   bool     quic_check_version(uint32_t, uint8_t);
   bool     quic_check_pointer_pos(const uint8_t *, const uint8_t *);
   bool     quic_obtain_tls_data(TLSData &);

   Initial_Secrets initial_secrets;

   quic_first_ver_dcidlen *quic_h1;
   quic_scidlen *quic_h2;

   const uint8_t *salt;

   uint8_t *header;
   const uint8_t *payload;

   uint16_t header_len;
   uint64_t payload_len;

   const uint8_t *dcid;
   const uint8_t *pkn;
   const uint8_t *sample;
   uint32_t version;

   uint8_t decrypted_payload[CURRENT_BUFFER_SIZE];
   uint8_t assembled_payload[CURRENT_BUFFER_SIZE];
   uint8_t tmp_header_mem[MAX_HEADER_LEN];
   uint8_t *final_payload;
   int parsed_initial;

   bool is_version2;

   char sni[BUFF_SIZE]        = { 0 };
   char user_agent[BUFF_SIZE] = { 0 };

   uint16_t quic_crypto_start;
   uint16_t quic_crypto_len;
   TLSParser tls_parser;
public:
   QUICParser();
   bool quic_start(const Packet&);
   void quic_get_sni(char *in);
   void quic_get_user_agent(char *in);
   void quic_get_version(uint32_t&);
};
}

// known versions

/*
 * 0x00000000 -- version negotiation
 * 0x00000001 -- newest , rfc 9000
 * 0xff0000xx -- drafts (IETF)
 * 0x709a50c4 -- quic version 2 -- newest draft (IETF)
 * 0xff020000 -- quic version 2 draft 00
 *
 *
 * Google
 * 0x51303433 -- Q043 -- no evidence -- based on google doc , this should not be encrypted
 * 0x51303434 -- Q044 -- no evidence
 * 0x51303436 -- Q046 -- wireshark cant parse -- based on google doc , this should not be encrypted
 * 0x51303530 -- Q050 -- looks like no TLS inside crypto
 *
 * 0x54303530 -- T050
 * 0x54303531 -- T051
 *
 *
 * MVFST
 * 0xfaceb001 -- should be draft 22
 * 0xfaceb002 -- should be draft 27
 * 0xfaceb003 -- ?
 * 0xfaceb00e -- experimental
 * 0xfaceb010 -- mvfst alias
 * 0xfaceb00f -- MVFST_INVALID
 * 0xfaceb011 -- MVFST_EXPERIMENTAL2
 * 0xfaceb013 -- MVFST_EXPERIMENTAL3
 */


// google salts

/*static const uint8_t hanshake_salt_draft_q50[SALT_LENGTH] = {
 * 0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
 * 0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45
 * };
 * static const uint8_t hanshake_salt_draft_t50[SALT_LENGTH] = {
 * 0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80,
 * 0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10
 * };
 * static const uint8_t hanshake_salt_draft_t51[SALT_LENGTH] = {
 * 0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50,
 * 0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d
 * };*/
