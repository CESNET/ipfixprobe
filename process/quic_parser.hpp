/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, CESNET z.s.p.o.
 */

/**
 * \file quic_parser.hpp
 * \brief Class for parsing quic traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * \date 2023
 */

#include "tls_parser.hpp"
#include <ipfixprobe/byte-utils.hpp>
#include <ipfixprobe/process.hpp>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#define HASH_SHA2_256_LENGTH 32
#define TLS13_AEAD_NONCE_LENGTH 12
#define SAMPLE_LENGTH 16
#define SALT_LENGTH 20
#define AES_128_KEY_LENGTH 16

#define TLS_EXT_SERVER_NAME 0
#define TLS_EXT_ALPN 16
// draf-33, draft-34 a rfc9001, have this value defined as 0x39 == 57
#define TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1 0x39
// draf-13 az draft-32 have this value defined as 0xffa5 == 65445
#define TLS_EXT_QUIC_TRANSPORT_PARAMETERS 0xffa5
// draf-02 az draft-12 have this value defined as 0x26 == 38
#define TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V2 0x26
#define TLS_EXT_GOOGLE_USER_AGENT 0x3129

// first byte (1) + version (4) + dcid length (1) + dcid (20) + scid length (1) + scid (20) +
// token length (variable so max is 8) + token (idk) + length (max 8) + pkt number (4)
// cant figure out if token length has any boundaries, theoretically 8 byte version of token length
// means 2^64 as max length
// 67 (header basic data) + 256 (max token length)
// TODO(jmuecke) I increased the token length, because I observered token_lengths up to 128. Revisit
// if larger tokens are common.
#define MAX_HEADER_LEN 67 + 256
#define BUFF_SIZE 255
#define CURRENT_BUFFER_SIZE 1500
// 8 because (1B QUIC LH, 4B Version, 1 B SCID LEN, 1B DCID LEN, Payload/Retry Token/Supported
// Version >= 1 B)
#define QUIC_MIN_PACKET_LENGTH 8
#define MAX_CID_LEN 20
#define QUIC_BIT 0b01000000
#define MAX_QUIC_TLS_EXT_LEN 30

namespace ipxp {

typedef struct __attribute__((packed)) quic_first_ver_dcidlen {
    uint8_t first_byte;
    uint32_t version;
    uint8_t dcid_len;
} quic_first_ver_dcidlen;

typedef struct __attribute__((packed)) quic_scidlen {
    uint8_t scid_len;
} quic_scidlen;

typedef struct Initial_Secrets {
    uint8_t key[AES_128_KEY_LENGTH];
    uint8_t iv[TLS13_AEAD_NONCE_LENGTH];
    uint8_t hp[AES_128_KEY_LENGTH];
} Initial_Secrets;

class QUICParser {
private:
    enum FRAME_TYPE {
        CRYPTO = 0x06,
        PADDING = 0x00,
        PING = 0x01,
        ACK1 = 0x02,
        ACK2 = 0x03,
        CONNECTION_CLOSE1 = 0x1C,
        CONNECTION_CLOSE2 = 0x1D
    };
    enum HKDF_LENGTHS {
        quic_key_hkdf_v1
        = sizeof("tls13 quic key") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
        quic_iv_hkdf_v1
        = sizeof("tls13 quic iv") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
        quic_hp_hkdf_v1
        = sizeof("tls13 quic hp") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
        quic_key_hkdf_v2
        = sizeof("tls13 quicv2 key") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
        quic_iv_hkdf_v2
        = sizeof("tls13 quicv2 iv") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
        quic_hp_hkdf_v2
        = sizeof("tls13 quicv2 hp") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t),
        quic_clientin_hkdf
        = sizeof("tls13 client in") + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t)
    };

    bool quic_initial_checks(const Packet&);
    void quic_initialze_arrays();
    bool quic_check_initial(uint8_t);
    bool quic_check_long_header(uint8_t);
    bool quic_create_initial_secrets();
    bool quic_decrypt_initial_header(const uint8_t* payload_pointer, uint64_t offset);
    bool quic_decrypt_payload();
    bool quic_reassemble_frames();
    bool quic_parse_tls();
    bool quic_obtain_version();
    bool quic_derive_secrets(uint8_t*);
    bool quic_check_frame_type(uint8_t*, FRAME_TYPE);
    void quic_skip_ack1(uint8_t*, uint64_t&);
    void quic_skip_ack2(uint8_t*, uint64_t&);
    void quic_skip_connection_close1(uint8_t*, uint64_t&);
    void quic_skip_connection_close2(uint8_t*, uint64_t&);
    void quic_copy_crypto(uint8_t*, const uint8_t*, uint64_t&);
    bool quic_encrypt_sample(uint8_t*);

    uint8_t quic_draft_version(uint32_t);
    uint64_t quic_get_variable_length(const uint8_t*, uint64_t&);
    bool quic_check_version(uint32_t, uint8_t);
    bool quic_check_pointer_pos(const uint8_t*, const uint8_t*);
    bool quic_obtain_tls_data(TLSData&);
    bool quic_set_server_port(const Packet& pkt);
    bool quic_check_min_initial_size(const Packet& pkt);
    bool quic_check_supported_version(const uint32_t version);
    bool quic_parser_tls_and_set_server_port(const Packet& pkt);
    bool quic_parse_initial_header(
        const Packet& pkt,
        const uint8_t* payload_pointer,
        const uint8_t* payload_end,
        uint64_t& offset);
    void quic_parse_packet_type(uint8_t packet0);

    Initial_Secrets initial_secrets;

    quic_first_ver_dcidlen* quic_h1;
    quic_scidlen* quic_h2;

    const uint8_t* salt;

    uint8_t* header;
    const uint8_t* payload;

    uint16_t header_len;
    uint64_t payload_len;
    uint8_t payload_len_offset;

    uint8_t packet_type;
    const uint8_t* dcid;
    uint8_t dcid_len;
    uint8_t* initial_dcid;
    uint8_t initial_dcid_len;
    const uint8_t* scid;
    uint8_t scid_len;
    const uint8_t* pkn;
    const uint8_t* sample;
    uint32_t version;
    uint64_t token_length;

    uint8_t pkn_len;

    uint8_t decrypted_payload[CURRENT_BUFFER_SIZE];
    uint8_t assembled_payload[CURRENT_BUFFER_SIZE];
    uint8_t tmp_header_mem[MAX_HEADER_LEN];
    uint8_t* final_payload;
    uint8_t zero_rtt;

    uint16_t quic_tls_ext_type[MAX_QUIC_TLS_EXT_LEN];
    uint8_t quic_tls_ext_type_pos;

    uint16_t quic_tls_extension_lengths[MAX_QUIC_TLS_EXT_LEN];
    uint8_t quic_tls_extension_lengths_pos;

    char quic_tls_ext[CURRENT_BUFFER_SIZE];
    uint16_t quic_tls_ext_pos;

    int parsed_initial;
    bool parsed_client_hello;
    uint16_t server_port;
    bool direction_to_server;

    bool is_version2;
    uint8_t tls_hs_type;

    char sni[BUFF_SIZE] = {0};
    char user_agent[BUFF_SIZE] = {0};

    uint16_t quic_crypto_start;
    uint16_t quic_crypto_len;
    TLSParser tls_parser;

    uint8_t packets;

public:
    enum PACKET_TYPE {
        INITIAL = 0b00,
        ZERO_RTT = 0b01,
        HANDSHAKE = 0b10,
        RETRY = 0b11,
        VERSION_NEGOTIATION = 0b111,
        UNKNOWN = 0xFF
    };
    enum PACKET_TYPE_FLAG {
        F_INITIAL = 0b00000001,
        F_ZERO_RTT = 0b00000010,
        F_HANDSHAKE = 0b00000100,
        F_RETRY = 0b00001000,
        F_VERSION_NEGOTIATION = 0b00010000,
        // We store the QUIC bit in the first bit of QUIC_PACKETS
        // The following enum should not be used, unless for extraction
        F_QUIC_BIT = 0b10000000
    };
    enum QUIC_CONSTANTS { QUIC_UNUSED_VARIABLE_LENGTH_INT = 0xFFFFFFFFFFFFFFFF };
    enum QUIC_VERSION {
        // Full versions
        faceebook1 = 0xfaceb001,
        faceebook2 = 0xfaceb002,
        facebook3 = 0xfaceb00d,
        facebook4 = 0xfaceb00f,
        facebook_experimental = 0xfaceb00e,
        facebook_experimental2 = 0xfaceb011,
        facebook_experimental3 = 0xfaceb013,
        facebook_mvfst_old = 0xfaceb000,
        facebook_mvfst_alias = 0xfaceb010,
        facebook_mvfst_alias2 = 0xfaceb012,
        facebook_v1_alias = 0xfaceb003,
        q_version2_draft00 = 0xff020000,
        q_version2_newest = 0x709a50c4,
        q_version2 = 0x6b3343cf,
        version_negotiation = 0x00000000,
        quic_newest = 0x00000001,
        picoquic1 = 0x50435130,
        picoquic2 = 0x50435131,
        // Patterns
        force_ver_neg_pattern = 0x0a0a0a0a,
        quant = 0x45474700,
        older_version = 0xff0000,
        quic_go = 0x51474f00,
        // unknown handshake salt TODO use version 1 as default?
        quicly = 0x91c17000,
        // https://github.com/microsoft/msquic/blob/d33bc56d5e11db52e2b34ae152ea598fd6e935c0/src/core/packet.c#L461
        // But version is different
        ms_quic = 0xabcd0000,

        ethz = 0xf0f0f0f0,
        telecom_italia = 0xf0f0f1f0,

        moz_quic = 0xf123f0c0,

        tencent_quic = 0x07007000,

        quinn_noise = 0xf0f0f2f0,

        quic_over_scion = 0x5c100000
    };

    QUICParser();
    void quic_get_zero_rtt(uint8_t& zero_rtt_toset);
    bool quic_parse_initial(const Packet&, const uint8_t* payload_end, uint64_t offset);
    void quic_get_sni(char* in);
    void quic_get_user_agent(char* in);
    void quic_get_version(uint32_t&);
    void quic_get_token_length(uint64_t&);
    void quic_get_dcid(char* in);
    void quic_get_scid(char* in);
    void quic_get_scid_len(uint8_t&);
    void quic_get_dcid_len(uint8_t&);
    void quic_get_parsed_initial(uint8_t&);
    void quic_get_packets(uint8_t&);
    uint8_t quic_get_parsed_ch();
    uint8_t quic_get_packet_type();
    uint16_t quic_get_server_port();
    bool quic_check_quic_long_header_packet(
        const Packet& pkt,
        char* initial_packet_dcid,
        uint8_t& initial_packet_dcid_length);
    bool quic_parse_headers(const Packet&, bool forceInitialParsing);
    bool quic_parse_header(
        const Packet& pkt,
        uint64_t& offset,
        uint8_t* payload_pointer,
        uint8_t* payload_end);
    bool quic_long_header_packet(const Packet& pkt);
    uint8_t quic_get_tls_hs_type();
    void quic_get_tls_ext_len(uint16_t& tls_ext_len_toset);
    void quic_get_tls_ext(char* in);
    void quic_get_tls_ext_type_len(uint16_t& tls_ext_type_len_toset);
    void quic_get_tls_ext_type(uint16_t* tls_ext_type_toset);

    void quic_parse_quic_bit(uint8_t packet0);
    void quic_get_tls_extension_lengths(uint16_t* tls_extensions_len);
    void quic_get_tls_extension_lengths_len(uint8_t& tls_extensions_length_len_toset);
    void quic_get_tls_extensions(char* in);
};

} // namespace ipxp

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
