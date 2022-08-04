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


#include <cstdint>
#include <cstring>
#include <ipfixprobe/process.hpp>

#define TLS_HANDSHAKE_CLIENT_HELLO           1
#define TLS_HANDSHAKE_SERVER_HELLO           2
#define TLS_EXT_SERVER_NAME                  0
#define TLS_EXT_ALPN                         16
// draf-33, draft-34 a rfc9001, have this value defined as 0x39 == 57
#define TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1 0x39
// draf-13 az draft-32 have this value defined as 0xffa5 == 65445
#define TLS_EXT_QUIC_TRANSPORT_PARAMETERS    0xffa5
// draf-02 az draft-12 have this value defined as 0x26 == 38
#define TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V2 0x26
#define TLS_EXT_GOOGLE_USER_AGENT            0x3129


namespace ipxp {
typedef struct TLSData {
   const uint8_t *start;
   const uint8_t *end;
   int            obejcts_parsed;
} TLSData;

struct __attribute__((packed)) tls_ext_sni {
   uint8_t  type;
   uint16_t length;
   /* Hostname bytes... */
};

struct __attribute__((packed)) tls_ext {
   uint16_t type;
   uint16_t length;
   /* Extension pecific data... */
};

union __attribute__((packed)) tls_version {
   uint16_t version;
   struct {
      uint8_t major;
      uint8_t minor;
   };
};

struct __attribute__((packed)) tls_handshake {
   uint8_t     type;
   uint8_t     length1; // length field is 3 bytes long...
   uint16_t    length2;
   tls_version version;

   /* Handshake data... */
};

#define TLS_HANDSHAKE 22
struct __attribute__((packed)) tls_rec {
   uint8_t     type;
   tls_version version;
   uint16_t    length;
   /* Record data... */
};

class TLSParser
{
private:
   tls_handshake *tls_hs;
public:
   TLSParser();
   bool tls_skip_random(TLSData&);
   bool tls_skip_sessid(TLSData&);
   bool tls_skip_cipher_suites(TLSData&);
   bool tls_skip_compression_met(TLSData&);
   bool tls_check_ext_len(TLSData&);
   bool tls_check_rec(TLSData&);
   void tls_get_server_name(TLSData &, char *, size_t);
   void tls_get_alpn(TLSData &, char *, size_t);

   void tls_get_quic_user_agent(TLSData &, char *, size_t);
   bool tls_check_handshake(TLSData&);
   bool tls_get_ja3_cipher_suites(std::string&, TLSData&);

   bool tls_is_grease_value(uint16_t);

   tls_handshake tls_get_handshake();
   uint8_t tls_get_hstype();
   std::string tls_get_version_ja3();
   std::string tls_get_ja3_ecpliptic_curves(TLSData &data);
   std::string tls_get_ja3_ec_point_formats(TLSData &data);
};
}
