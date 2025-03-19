/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, CESNET z.s.p.o.
 */

/**
 * \file quic_parser.cpp
 * \brief Class for parsing quic traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * \date 2023
 */

#include "quic_parser.hpp"

#ifdef DEBUG_QUIC
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_QUIC
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

namespace ipxp {
QUICParser::QUICParser()
{
	quic_h1 = nullptr;
	quic_h2 = nullptr;
	payload = nullptr;

	header_len = 0;
	payload_len = 0;
	payload_len_offset = 0;

	dcid = nullptr;
	dcid_len = 0;
	initial_dcid = nullptr;
	initial_dcid_len = 0;
	scid = nullptr;
	scid_len = 0;
	pkn = nullptr;
	sample = nullptr;
	salt = nullptr;
	final_payload = nullptr;
	parsed_initial = 0;
	is_version2 = false;
	packet_type = UNKNOWN;
	packets = 0;
	token_length = QUIC_UNUSED_VARIABLE_LENGTH_INT;
	zero_rtt = 0;
	server_port = 0;
	pkn_len = 0;
	tls_hs_type = 0;
	parsed_client_hello = false;

	memset(quic_tls_ext_type, 0, sizeof(quic_tls_ext_type));
	quic_tls_ext_type_pos = 0;

	memset(quic_tls_extension_lengths, 0, sizeof(quic_tls_extension_lengths));
	quic_tls_extension_lengths_pos = 0;

	memset(quic_tls_ext, 0, sizeof(quic_tls_ext));
	quic_tls_ext_pos = 0;
}
void QUICParser::quic_get_tls_ext_type(uint16_t* tls_ext_type_toset)
{
	// *2 since 16 bit instead of 8
	memcpy(tls_ext_type_toset, quic_tls_ext_type, quic_tls_ext_type_pos * 2);
}

void QUICParser::quic_get_tls_ext_type_len(uint16_t& tls_ext_type_len_toset)
{
	tls_ext_type_len_toset = quic_tls_ext_type_pos;
}

void QUICParser::quic_get_tls_ext(char* in)
{
	memcpy(in, quic_tls_ext, quic_tls_ext_pos);
	return;
}

void QUICParser::quic_get_tls_ext_len(uint16_t& tls_ext_len_toset)
{
	tls_ext_len_toset = quic_tls_ext_pos;
}

void QUICParser::quic_get_tls_extension_lengths(uint16_t* tls_extensions_len)
{
	memcpy(tls_extensions_len, quic_tls_extension_lengths, quic_tls_extension_lengths_pos * 2);
}

void QUICParser::quic_get_tls_extension_lengths_len(uint8_t& tls_extensions_length_len_toset)
{
	tls_extensions_length_len_toset = quic_tls_extension_lengths_pos;
}

uint8_t QUICParser::quic_get_packet_type()
{
	return packet_type;
}

uint8_t QUICParser::quic_get_parsed_ch()
{
	if (parsed_client_hello) {
		return 1;
	}
	return 0;
}

uint8_t QUICParser::quic_get_tls_hs_type()
{
	return tls_hs_type;
}

void QUICParser::quic_get_zero_rtt(uint8_t& zero_rtt_toset)
{
	zero_rtt_toset = zero_rtt;
}

void QUICParser::quic_get_version(uint32_t& version_toset)
{
	version_toset = version;
	return;
}

void QUICParser::quic_get_packets(uint8_t& packets_toset)
{
	packets_toset = packets;
	return;
}

void QUICParser::quic_get_token_length(uint64_t& token_len_toset)
{
	token_len_toset = token_length;
	return;
}

uint16_t QUICParser::quic_get_server_port()
{
	return server_port;
}

void QUICParser::quic_get_parsed_initial(uint8_t& to_set)
{
	to_set = parsed_initial;
	return;
}

void QUICParser::quic_get_dcid_len(uint8_t& scid_length_toset)
{
	scid_length_toset = dcid_len;
	return;
}

void QUICParser::quic_get_scid_len(uint8_t& scid_length_toset)
{
	scid_length_toset = scid_len;
	return;
}

void QUICParser::quic_get_tls_extensions(char* in)
{
	memcpy(in, quic_tls_ext, quic_tls_ext_pos);
	return;
}

void QUICParser::quic_get_dcid(char* in)
{
	memcpy(in, dcid, dcid_len);
	return;
}

void QUICParser::quic_get_scid(char* in)
{
	memcpy(in, scid, scid_len);
	return;
}

void QUICParser::quic_get_sni(char* in)
{
	memcpy(in, sni, BUFF_SIZE);
	return;
}

void QUICParser::quic_get_user_agent(char* in)
{
	memcpy(in, user_agent, BUFF_SIZE);
	return;
}

bool QUICParser::quic_check_pointer_pos(const uint8_t* current, const uint8_t* end)
{
	if (current < end)
		return true;

	return false;
}

uint64_t QUICParser::quic_get_variable_length(const uint8_t* start, uint64_t& offset)
{
	uint64_t tmp = 0;
	if (offset >= CURRENT_BUFFER_SIZE - 1) {
		DEBUG_MSG("Error, buffer overflow\n");
		offset++;
		return 0;
	}
	uint8_t two_bits = *(start + offset) & 0xC0;

	switch (two_bits) {
	case 0:
		tmp = *(start + offset) & 0x3F;
		offset += sizeof(uint8_t);
		return tmp;
	case 64:
		if (offset >= CURRENT_BUFFER_SIZE - 2) {
			DEBUG_MSG("Error, buffer overflow\n");
			offset += 2;
			return 0;
		}
		tmp = be16toh(*(uint16_t*) (start + offset)) & 0x3FFF;
		offset += sizeof(uint16_t);
		return tmp;
	case 128:
		if (offset >= CURRENT_BUFFER_SIZE - 4) {
			DEBUG_MSG("Error, buffer overflow\n");
			offset += 4;
			return 0;
		}
		tmp = be32toh(*(uint32_t*) (start + offset)) & 0x3FFFFFFF;
		offset += sizeof(uint32_t);
		return tmp;
	case 192:
		if (offset >= CURRENT_BUFFER_SIZE - 8) {
			DEBUG_MSG("Error, buffer overflow\n");
			offset += 8;
			return 0;
		}
		tmp = be64toh(*(uint64_t*) (start + offset)) & 0x3FFFFFFFFFFFFFFF;
		offset += sizeof(uint64_t);
		return tmp;
	default:
		return 0;
	}
} // QUICParser::quic_get_variable_length

bool QUICParser::quic_parse_tls_extensions()
{
	const bool extensions_parsed = tls_parser.parse_extensions([this](
																   uint16_t extension_type,
																   const uint8_t* extension_payload,
																   uint16_t extension_length) {
		if (extension_type == TLS_EXT_SERVER_NAME && extension_length != 0) {
			tls_parser.parse_server_names(extension_payload, extension_length);
		} else if (
			(extension_type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1
			 || extension_type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS
			 || extension_type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V2)
			&& extension_length != 0) {
			tls_parser.parse_quic_user_agent(extension_payload, extension_length);
		}
		if (quic_tls_ext_pos + extension_length < CURRENT_BUFFER_SIZE) {
#ifndef QUIC_CH_FULL_TLS_EXT
			if (extension_type == TLS_EXT_ALPN
				|| extension_type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1
				|| extension_type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS
				|| extension_type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V2) {
#endif
				memcpy(quic_tls_ext + quic_tls_ext_pos, extension_payload, extension_length);
				quic_tls_ext_pos += extension_length;
#ifndef QUIC_CH_FULL_TLS_EXT
			}
#endif
		}
		tls_parser.add_extension(extension_type, extension_length);
	});
	if (!extensions_parsed) {
		return false;
	}
	tls_parser.save_server_names(sni, BUFF_SIZE);
	tls_parser.save_quic_user_agent(user_agent, BUFF_SIZE);

	const size_t copy_count
		= std::min<size_t>(tls_parser.get_extensions().size(), MAX_QUIC_TLS_EXT_LEN);
	std::transform(
		tls_parser.get_extensions().begin(),
		tls_parser.get_extensions().begin() + static_cast<ssize_t>(copy_count),
		std::begin(quic_tls_ext_type),
		[](const TLSExtension& typeLength) { return typeLength.type; });
	std::transform(
		tls_parser.get_extensions().begin(),
		tls_parser.get_extensions().begin() + static_cast<ssize_t>(copy_count),
		std::begin(quic_tls_extension_lengths),
		[](const TLSExtension& typeLength) { return typeLength.length; });
	quic_tls_ext_type_pos = quic_tls_extension_lengths_pos = copy_count;
	return true;
}

bool QUICParser::quic_parse_tls()
{
	if (!tls_parser.parse_quic_tls(final_payload + quic_crypto_start, quic_crypto_len)) {
		return false;
	}
	return quic_parse_tls_extensions();
}

uint8_t QUICParser::quic_draft_version(uint32_t version)
{
	// Calculate potential draft version
	uint8_t draftversion = (uint8_t) version & 0xff;
	// this is IETF implementation, older version used
	if ((version >> 8) == older_version) {
		if (draftversion >= 1 && draftversion <= 34) {
			return (uint8_t) version;
		}
	}
	// This exists since version 29, but is still present in RFC9000.
	if ((version & 0x0F0F0F0F) == force_ver_neg_pattern) {
		// Version 1
		return 35;
	}

	// Without further knowledge we assume QUIC version 1.

	// Last Nybble zero
	switch (version & 0xfffffff0) {
	case ms_quic:
		return 29;
	case ethz:
	case telecom_italia:
	case tencent_quic:
	case quinn_noise:
	case quic_over_scion:
		return 35;
	case moz_quic:
		return 14;
	}

	// Last Byte zero
	switch (version & 0xffffff00) {
	case quant:
		return draftversion;
	case quic_go:
	case quicly:
		return 35;
	}

	switch (version) {
	case version_negotiation:
		// TODO verify: We return a value that has no salt assigned.
		return 1;
	// older mvfst version, but still used, based on draft 22, but salt 21 used
	case (facebook_mvfst_old):
		return 20;
	case (faceebook1):
		return 22;
	// more used atm, salt 23 used
	case faceebook2:
	// 3 and 4 use default salt 23 according to mvfst:
	// https://github.com/facebook/mvfst/blob/e89b990eaec5787a7dca7750362ea530e7703bdf/quic/handshake/HandshakeLayer.cpp#L27
	case facebook3:
	case facebook4:
	case facebook_experimental:
	case facebook_experimental2:
	case facebook_experimental3:
	case facebook_mvfst_alias:
	case facebook_mvfst_alias2:
		return 27;
	// version 2 draft 00
	case quic_newest:
		return 35;
	case picoquic1:
	case picoquic2:
		return 36;
	case q_version2_draft00:
	// newest
	case q_version2_newest:
		is_version2 = true;
		return 100;
	case q_version2:
		is_version2 = true;
		return 101;
	case facebook_v1_alias:
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
	static const uint8_t handshake_salt_draft_7[SALT_LENGTH]
		= {0xaf, 0xc8, 0x24, 0xec, 0x5f, 0xc7, 0x7e, 0xca, 0x1e, 0x9d,
		   0x36, 0xf3, 0x7f, 0xb2, 0xd4, 0x65, 0x18, 0xc3, 0x66, 0x39};
	// this salt is used to draft 10-16
	static const uint8_t handshake_salt_draft_10[SALT_LENGTH]
		= {0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96,
		   0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38};
	// this salt is used to draft 17-20
	static const uint8_t handshake_salt_draft_17[SALT_LENGTH]
		= {0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef,
		   0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0};
	// this salt is used to draft 21-22
	static const uint8_t handshake_salt_draft_21[SALT_LENGTH]
		= {0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
		   0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a};
	// this salt is used to draft 23-28
	static const uint8_t handshake_salt_draft_23[SALT_LENGTH] = {
		0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
		0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
	};
	// this salt is used to draft 29-32
	static const uint8_t handshake_salt_draft_29[SALT_LENGTH]
		= {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
		   0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99};
	// newest 33 -
	static const uint8_t handshake_salt_v1[SALT_LENGTH]
		= {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		   0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
	static const uint8_t handshake_salt_v2_provisional[SALT_LENGTH]
		= {0xa7, 0x07, 0xc2, 0x03, 0xa5, 0x9b, 0x47, 0x18, 0x4a, 0x1d,
		   0x62, 0xca, 0x57, 0x04, 0x06, 0xea, 0x7a, 0xe3, 0xe5, 0xd3};
	static const uint8_t handshake_salt_v2[SALT_LENGTH]
		= {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		   0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};
	// picoquic
	static const uint8_t handshake_salt_picoquic_internal[SALT_LENGTH]
		= {0x30, 0x67, 0x16, 0xd7, 0x63, 0x75, 0xd5, 0x55, 0x4b, 0x2f,
		   0x60, 0x5e, 0xef, 0x78, 0xd8, 0x33, 0x3d, 0xc1, 0xca, 0x36};

	if (version == version_negotiation) {
		DEBUG_MSG("Error, version negotiation\n");
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
	} else if (!is_version2 && quic_check_version(version, 35)) {
		salt = handshake_salt_v1;
	} else if (!is_version2 && quic_check_version(version, 36)) {
		salt = handshake_salt_picoquic_internal;
	} else if (is_version2 && quic_check_version(version, 100)) {
		salt = handshake_salt_v2_provisional;
	} else if (is_version2 && quic_check_version(version, 101)) {
		salt = handshake_salt_v2;
	} else {
		DEBUG_MSG("Error, version not supported\n");
		return false;
	}

	return true;
} // QUICParser::quic_obtain_version

bool expand_label(
	const char* label_prefix,
	const char* label,
	const uint8_t* context_hash,
	uint8_t context_length,
	uint16_t desired_len,
	uint8_t* out,
	uint8_t& out_len)
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

	(void) context_hash;

	const unsigned int label_prefix_length = (unsigned int) strlen(label_prefix);
	const unsigned int label_length = (unsigned int) strlen(label);

	const uint8_t label_vector_length = label_prefix_length + label_length;
	const uint16_t length = ntohs(desired_len);

	out_len = sizeof(length) + sizeof(label_vector_length) + label_vector_length
		+ sizeof(context_length);

	// copy length
	memcpy(out, &length, sizeof(length));
	// copy whole label length as described above
	memcpy(out + sizeof(length), &label_vector_length, sizeof(label_vector_length));
	// copy label prefix ("tls13 ")
	memcpy(out + sizeof(length) + sizeof(label_vector_length), label_prefix, label_prefix_length);
	// copy actual label
	memcpy(
		out + sizeof(length) + sizeof(label_vector_length) + label_prefix_length,
		label,
		label_length);
	// copy context length (should be 0)
	memcpy(
		out + sizeof(length) + sizeof(label_vector_length) + label_prefix_length + label_length,
		&context_length,
		sizeof(context_length));
	return true;
}

bool quic_derive_n_set(
	uint8_t* secret,
	uint8_t* expanded_label,
	uint8_t size,
	size_t output_len,
	uint8_t* store_data)
{
	EVP_PKEY_CTX* pctx;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (1 != EVP_PKEY_derive_init(pctx)) {
		DEBUG_MSG("Error, context initialization failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
		DEBUG_MSG("Error, mode initialization failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())) {
		DEBUG_MSG("Error, message digest initialization failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx, expanded_label, size)) {
		DEBUG_MSG("Error, info initialization failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, HASH_SHA2_256_LENGTH)) {
		DEBUG_MSG("Error, key initialization failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_derive(pctx, store_data, &output_len)) {
		DEBUG_MSG("Error, HKDF-Expand derivation failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	EVP_PKEY_CTX_free(pctx);
	return true;
} // QUICPlugin::quic_derive_n_set

bool QUICParser::quic_derive_secrets(uint8_t* secret)
{
	uint8_t len_quic_key;
	uint8_t len_quic_iv;
	uint8_t len_quic_hp;

	// expand label for other initial secrets
	if (!is_version2) {
		uint8_t quic_key[quic_key_hkdf_v1] = {0};
		uint8_t quic_iv[quic_iv_hkdf_v1] = {0};
		uint8_t quic_hp[quic_hp_hkdf_v1] = {0};
		expand_label("tls13 ", "quic key", NULL, 0, AES_128_KEY_LENGTH, quic_key, len_quic_key);
		expand_label("tls13 ", "quic iv", NULL, 0, TLS13_AEAD_NONCE_LENGTH, quic_iv, len_quic_iv);
		expand_label("tls13 ", "quic hp", NULL, 0, AES_128_KEY_LENGTH, quic_hp, len_quic_hp);
		// use HKDF-Expand to derive other secrets
		if (!quic_derive_n_set(
				secret,
				quic_key,
				len_quic_key,
				AES_128_KEY_LENGTH,
				initial_secrets.key)
			|| !quic_derive_n_set(
				secret,
				quic_iv,
				len_quic_iv,
				TLS13_AEAD_NONCE_LENGTH,
				initial_secrets.iv)
			|| !quic_derive_n_set(
				secret,
				quic_hp,
				len_quic_hp,
				AES_128_KEY_LENGTH,
				initial_secrets.hp)) {
			DEBUG_MSG("Error, derivation of initial secrets failed\n");
			return false;
		}
	} else {
		uint8_t quic_key[quic_key_hkdf_v2] = {0};
		uint8_t quic_iv[quic_iv_hkdf_v2] = {0};
		uint8_t quic_hp[quic_hp_hkdf_v2] = {0};
		expand_label("tls13 ", "quicv2 key", NULL, 0, AES_128_KEY_LENGTH, quic_key, len_quic_key);
		expand_label("tls13 ", "quicv2 iv", NULL, 0, TLS13_AEAD_NONCE_LENGTH, quic_iv, len_quic_iv);
		expand_label("tls13 ", "quicv2 hp", NULL, 0, AES_128_KEY_LENGTH, quic_hp, len_quic_hp);

		// use HKDF-Expand to derive other secrets
		if (!quic_derive_n_set(
				secret,
				quic_key,
				len_quic_key,
				AES_128_KEY_LENGTH,
				initial_secrets.key)
			|| !quic_derive_n_set(
				secret,
				quic_iv,
				len_quic_iv,
				TLS13_AEAD_NONCE_LENGTH,
				initial_secrets.iv)
			|| !quic_derive_n_set(
				secret,
				quic_hp,
				len_quic_hp,
				AES_128_KEY_LENGTH,
				initial_secrets.hp)) {
			DEBUG_MSG("Error, derivation of initial secrets failed\n");
			return false;
		}
	}

	return true;
} // QUICPlugin::quic_derive_secrets

bool QUICParser::quic_create_initial_secrets()
{
	// Set DCID if not set by previous packet
	if (initial_dcid_len == 0) {
		initial_dcid_len = dcid_len;
		initial_dcid = (uint8_t*) dcid;
	}

	uint8_t extracted_secret[HASH_SHA2_256_LENGTH] = {0};
	size_t extr_len = HASH_SHA2_256_LENGTH;

	uint8_t expanded_secret[HASH_SHA2_256_LENGTH] = {0};
	size_t expd_len = HASH_SHA2_256_LENGTH;

	uint8_t expand_label_buffer[quic_clientin_hkdf];
	uint8_t expand_label_len;

	// HKDF-Extract
	EVP_PKEY_CTX* pctx;

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
	if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, initial_dcid, initial_dcid_len)) {
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
	expand_label(
		"tls13 ",
		"client in",
		NULL,
		0,
		HASH_SHA2_256_LENGTH,
		expand_label_buffer,
		expand_label_len);
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

bool QUICParser::quic_encrypt_sample(uint8_t* plaintext)
{
	int len = 0;
	EVP_CIPHER_CTX* ctx;

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

bool QUICParser::quic_decrypt_initial_header(const uint8_t* payload_pointer, uint64_t offset)
{
	(void) offset;

	uint8_t plaintext[SAMPLE_LENGTH];
	uint8_t mask[5] = {0};
	uint8_t full_pkn[4] = {0};
	uint8_t first_byte = 0;
	uint32_t packet_number = 0;

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
	pkn_len = (first_byte & 0x03) + 1;

	// after de-obfuscating pkn, we know exactly pkn length so we can correctly adjust start of
	// payload
	payload = payload + pkn_len;
	payload_len = payload_len - pkn_len;
	if (payload_len > CURRENT_BUFFER_SIZE) {
		DEBUG_MSG("Payload length underflow\n");
		return false;
	}
	header_len = payload - payload_pointer;
	if (header_len > MAX_HEADER_LEN) {
		DEBUG_MSG("Header length too long\n");
		return false;
	}

	memcpy(tmp_header_mem, payload_pointer, header_len);
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
	phton64(
		initial_secrets.iv + sizeof(initial_secrets.iv) - 8,
		pntoh64(initial_secrets.iv + sizeof(initial_secrets.iv) - 8) ^ packet_number);
	return true;
} // QUICPlugin::quic_decrypt_initial_header

bool QUICParser::quic_decrypt_payload()
{
	uint8_t atag[16] = {0};
	int len;

	/* Input is --> "header || ciphertext (buffer) || auth tag (16 bytes)" */

	if (payload_len <= 16 || payload_len > CURRENT_BUFFER_SIZE) {
		DEBUG_MSG("Payload decryption error, ciphertext too short or long\n");
		return false;
	}
	// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-34#section-5.3
	// "These cipher suites have a 16-byte authentication tag and produce an output 16 bytes larger
	// than their input." adjust length because last 16 bytes are authentication tag
	payload_len -= 16;
	payload_len_offset = 16;

	memcpy(&atag, &payload[payload_len], 16);
	EVP_CIPHER_CTX* ctx;

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

bool QUICParser::quic_check_frame_type(uint8_t* where, FRAME_TYPE frame_type)
{
	return (*where) == frame_type;
}

inline void QUICParser::quic_skip_ack1(uint8_t* start, uint64_t& offset)
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
	offset++;
	quic_get_variable_length(start, offset);
	quic_get_variable_length(start, offset);
	uint64_t quic_ack_range_count = quic_get_variable_length(start, offset);

	quic_get_variable_length(start, offset);

	for (uint64_t x = 0; x < quic_ack_range_count && offset < CURRENT_BUFFER_SIZE; x++) {
		quic_get_variable_length(start, offset);
		quic_get_variable_length(start, offset);
	}
	return;
}

inline void QUICParser::quic_skip_ack2(uint8_t* start, uint64_t& offset)
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
	offset++;
	quic_get_variable_length(start, offset);
	quic_get_variable_length(start, offset);
	uint64_t quic_ack_range_count = quic_get_variable_length(start, offset);

	quic_get_variable_length(start, offset);

	for (uint64_t x = 0; x < quic_ack_range_count && offset < CURRENT_BUFFER_SIZE; x++) {
		quic_get_variable_length(start, offset);
		quic_get_variable_length(start, offset);
	}
	quic_get_variable_length(start, offset);
	quic_get_variable_length(start, offset);
	quic_get_variable_length(start, offset);
	return;
}

inline void QUICParser::quic_skip_connection_close1(uint8_t* start, uint64_t& offset)
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
	offset++;
	quic_get_variable_length(start, offset);
	quic_get_variable_length(start, offset);
	uint64_t reason_phrase_length = quic_get_variable_length(start, offset);

	offset += reason_phrase_length;
	return;
}

inline void QUICParser::quic_skip_connection_close2(uint8_t* start, uint64_t& offset)
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
	offset++;
	quic_get_variable_length(start, offset);
	uint64_t reason_phrase_length = quic_get_variable_length(start, offset);

	offset += reason_phrase_length;
	return;
}

inline void QUICParser::quic_copy_crypto(uint8_t* start, const uint8_t* end, uint64_t& offset)
{
	offset += 1;
	uint32_t frame_offset = quic_get_variable_length(start, offset);
	uint32_t frame_length = quic_get_variable_length(start, offset);

	if (end < (start + offset)) {
		// avoid source buffer overflow
		quic_crypto_len += frame_length;
		offset += frame_length;
		return;
	}

	frame_offset = std::min(frame_offset, (uint32_t) (CURRENT_BUFFER_SIZE - 1));
	frame_length = std::min((uint32_t) (CURRENT_BUFFER_SIZE - 1 - frame_offset), frame_length);
	// avoid memory overlap in memcpy when not enought space in source buffer
	frame_length = std::min(frame_length, (uint32_t) (end - (start + offset)));

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
	quic_crypto_len = 0;

	uint64_t offset = 0;
	uint8_t* payload_end = decrypted_payload + payload_len;
	uint8_t* current = decrypted_payload + offset;

	if (payload_len > CURRENT_BUFFER_SIZE) {
		DEBUG_MSG("Payload length too long\n");
		return false;
	}

	while (quic_check_pointer_pos(current, payload_end)) {
		// https://www.rfc-editor.org/rfc/rfc9000.html#name-frames-and-frame-types
		// only those frames can occure in initial packets
		if (quic_check_frame_type(current, CRYPTO)) {
			quic_copy_crypto(decrypted_payload, payload_end, offset);
		} else if (quic_check_frame_type(current, ACK1)) {
			quic_skip_ack1(decrypted_payload, offset);
		} else if (quic_check_frame_type(current, ACK2)) {
			quic_skip_ack2(decrypted_payload, offset);
		} else if (quic_check_frame_type(current, CONNECTION_CLOSE1)) {
			quic_skip_connection_close1(decrypted_payload, offset);
		} else if (quic_check_frame_type(current, CONNECTION_CLOSE2)) {
			quic_skip_connection_close2(decrypted_payload, offset);
		} else if (
			quic_check_frame_type(current, PADDING) || quic_check_frame_type(current, PING)) {
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

bool QUICParser::quic_check_long_header(uint8_t packet0)
{
	// We  test for 1 in the fist position = long header
	// We ignore the QUIC bit, as it might be greased
	// https://datatracker.ietf.org/doc/html/rfc9287
	return (packet0 & 0x80) == 0x80;
}

bool QUICParser::quic_check_initial(uint8_t packet0)
{
	// The fixed bit, might be greased. We assume greasing for all packets
	// RFC 9287
	// version 1 (header form:long header(1) | fixed bit:fixed(1/0) | long packet type:initial(00)
	// --> 1000 --> 8)
	if ((packet0 & 0xB0) == 0x80) {
		return true;
	}
	// version 2 (header form:long header(1) | fixed bit:fixed(1)/0 | long packet type:initial(01)
	// --> 1001 --> 9)
	else if (is_version2 && ((packet0 & 0xB0) == 0x90)) {
		return true;
	} else {
		return false;
	}
}

bool QUICParser::quic_check_min_initial_size(const Packet& pkt)
{
	if (pkt.payload_len < QUIC_MIN_PACKET_LENGTH) {
		return false;
	}
	return true;
}

uint32_t read_uint32_t(const uint8_t* ptr, uint8_t offset)
{
	uint32_t val;
	memcpy(&val, ptr + offset, sizeof(uint32_t));
	return val;
}

bool QUICParser::quic_check_supported_version(const uint32_t version)
{
	uint8_t draft_version = quic_draft_version(version);
	return (draft_version > 0) && (draft_version < 255);
}

bool QUICParser::quic_long_header_packet(const Packet& pkt)
{
	// UDP check, Initial packet check, QUIC min long header size, QUIC version check,
	if (pkt.ip_proto != 17 || !quic_check_long_header(pkt.payload[0])
		|| !(quic_check_min_initial_size(pkt))
		|| !(quic_check_supported_version(ntohl(read_uint32_t(pkt.payload, 1))))) {
		DEBUG_MSG(
			"Packet is not Initial or does not contains LONG HEADER or is not long enough or is "
			"not a supported QUIC version\n");
		return false;
	}
	return true;
}

bool QUICParser::quic_parse_initial_header(
	const Packet& pkt,
	const uint8_t* payload_pointer,
	const uint8_t* payload_end,
	uint64_t& offset)
{
	(void) pkt;

	token_length = quic_get_variable_length(payload_pointer, offset);
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

	// This should not cause an offset.
	//   offset += sizeof(uint8_t) * 4;
	sample = (payload_pointer + offset + 4 * sizeof(uint8_t));

	if (!quic_check_pointer_pos((payload_pointer + offset + 4 * sizeof(uint8_t)), payload_end)) {
		return false;
	}
	return true;
}

void QUICParser::quic_parse_quic_bit(uint8_t packet0)
{
	// Contains value of the first included QUIC bit (in the case of coalesced packets)
	// Always the second msb.
	// Note: no meaning if in Version negotiation.

	packets |= (packet0 & QUIC_BIT) << 1;
}

void QUICParser::quic_parse_packet_type(uint8_t packet0)
{
	if (version == version_negotiation) {
		packets |= F_VERSION_NEGOTIATION;
		packet_type = VERSION_NEGOTIATION;
		return;
	}

	packet_type = (packet0 & 0b00110000) >> 4;
	if (!is_version2) {
		switch (packet_type) {
		case 0b00:
			packets |= F_INITIAL;
			break;
		case 0b01:
			packets |= F_ZERO_RTT;
			break;
		case 0b10:
			packets |= F_HANDSHAKE;
			break;
		case 0b11:
			packets |= F_RETRY;
			break;
		}
	}
	if (is_version2) {
		switch (packet_type) {
		case 0b01:
			packet_type = INITIAL;
			packets |= F_INITIAL;
			break;
		case 0b10:
			packet_type = ZERO_RTT;
			packets |= F_ZERO_RTT;
			break;
		case 0b11:
			packet_type = HANDSHAKE;
			packets |= F_HANDSHAKE;
			break;
		case 0b00:
			packet_type = RETRY;
			packets |= F_RETRY;
			break;
		}
	}
}

bool QUICParser::quic_parse_header(
	const Packet& pkt,
	uint64_t& offset,
	uint8_t* payload_pointer,
	uint8_t* payload_end)
{
	(void) pkt;

	if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
		return false;
	}

	quic_h1 = (quic_first_ver_dcidlen*) (payload_pointer + offset);

	if (!quic_check_long_header(quic_h1->first_byte)) {
		// If not long header packet -> short header packet. Do not analyze.
		return false;
	}

	if (!quic_obtain_version()) {
		DEBUG_MSG("Error, version not supported\n");
		return false;
	}

	offset += sizeof(quic_first_ver_dcidlen);

	if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
		return false;
	}

	if (quic_h1->dcid_len != 0) {
		if (quic_h1->dcid_len > MAX_CID_LEN) {
			DEBUG_MSG("Recieved DCID longer than supported. dcid_len=%d \n", dcid_len);
			return false;
		}
		dcid = (payload_pointer + offset);
		dcid_len = quic_h1->dcid_len;
		offset += quic_h1->dcid_len;
	}

	if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
		return false;
	}

	quic_h2 = (quic_scidlen*) (payload_pointer + offset);

	offset += sizeof(quic_scidlen);

	if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
		return false;
	}

	if (quic_h2->scid_len != 0) {
		if (quic_h2->scid_len > MAX_CID_LEN) {
			DEBUG_MSG("Recieved SCID longer than supported. scid_len=%d \n", scid_len);
			return false;
		}
		scid = (payload_pointer + offset);
		scid_len = quic_h2->scid_len;
		offset += quic_h2->scid_len;
	}

	if (!quic_check_pointer_pos((payload_pointer + offset), payload_end)) {
		return false;
	}

	quic_parse_packet_type(quic_h1->first_byte);

	return true;
}

bool QUICParser::quic_parse_headers(const Packet& pkt, bool forceInitialParsing)
{
	(void) pkt;
	(void) forceInitialParsing;

	uint8_t* pkt_payload_pointer = (uint8_t*) pkt.payload;
	uint8_t* payload_pointer = pkt_payload_pointer;
	uint64_t offset = 0;

	uint8_t* pkt_payload_end = payload_pointer + pkt.payload_len;

	// Handle coalesced packets
	// 7 because (1B QUIC LH, 4B Version, 1 B SCID LEN, 1B DCID LEN)
	uint64_t stored_payload_len;
	while (pkt.payload + offset + QUIC_MIN_PACKET_LENGTH <= pkt.payload + pkt.payload_len) {
		payload_pointer = pkt_payload_pointer + offset;

		if (!quic_parse_header(pkt, offset, pkt_payload_pointer, pkt_payload_end)) {
			break;
		}

		switch (packet_type) {
		case ZERO_RTT:
			payload_len = quic_get_variable_length(pkt_payload_pointer, offset);
			if (zero_rtt < 0xFF) {
				zero_rtt += 1;
			}
			offset += payload_len;
			break;
		case HANDSHAKE:
			payload_len = quic_get_variable_length(pkt_payload_pointer, offset);
			if (payload_len > CURRENT_BUFFER_SIZE) {
				return false;
			}
			offset += payload_len;
			break;
		case INITIAL:
			if (!quic_parse_initial_header(pkt, pkt_payload_pointer, pkt_payload_end, offset)) {
				return false;
			}
			stored_payload_len = payload_len;
			if (!parsed_initial) {
				// Not yet parsed a CH, try to parse as CH with inherited DCID
				quic_parse_initial(pkt, pkt_payload_pointer, offset);
				// If still not parsed, try with DCID from current packet.
				// Session resumption is such a case.
				if (!parsed_initial) {
					quic_tls_extension_lengths_pos = 0;
					// len = 0 forces reading DCID from current packet
					initial_dcid_len = 0;
					// Increment by tag_len, since subsequent function is not stateless.
					payload_len += payload_len_offset;
					// Undo side effect from QUICParser::quic_decrypt_initial_header
					payload = payload - pkn_len;
					payload_len += pkn_len;
					quic_parse_initial(pkt, pkt_payload_pointer, offset);
				}
			}
			offset += stored_payload_len;
			break;
		case RETRY:
			// 16 - Integrity tag
			token_length = pkt_payload_end - payload_pointer - offset - 16;
			if (!quic_check_pointer_pos((pkt_payload_pointer + offset), pkt_payload_end)) {
				return false;
			}
			offset += token_length;
			if (!quic_check_pointer_pos((pkt_payload_pointer + offset), pkt_payload_end)) {
				return false;
			}
			break;
		}

		if (!quic_set_server_port(pkt)) {
			DEBUG_MSG("Error, extracting server port");
			return false;
		}

		if (packet_type == RETRY) {
			break;
		}
	}

	// Update packet type to most specific, i.e., Initial
	if (packets & F_INITIAL) {
		packet_type = INITIAL;
	}

	return packets;
} // QUICPlugin::quic_parse_data

bool QUICParser::quic_set_server_port(const Packet& pkt)
{
	if (!tls_parser.get_handshake().has_value()) {
		return false;
	}

	switch (packet_type) {
	case INITIAL:
		tls_hs_type = tls_parser.get_handshake()->type;
		if (tls_hs_type == 1) {
			server_port = pkt.dst_port;
		} else if (tls_hs_type == 2) {
			// Won't be reached, since we don't supply the OCCID to quic_parser
			server_port = pkt.src_port;
		}
		// e.g. ACKs do not reveal direction
		break;
	case VERSION_NEGOTIATION:
	case RETRY:
		server_port = pkt.src_port;
		break;
	case ZERO_RTT:
		server_port = pkt.dst_port;
		break;
	case HANDSHAKE:
		// Does not reveal the direction
		break;
	}
	return true;
}

bool QUICParser::quic_check_quic_long_header_packet(
	const Packet& pkt,
	char* initial_packet_dcid,
	uint8_t& initial_packet_dcid_length)
{
	initial_dcid_len = initial_packet_dcid_length;
	initial_dcid = (uint8_t*) initial_packet_dcid;

	quic_parse_quic_bit(pkt.payload[0]);

	if (!quic_long_header_packet(pkt)) {
		return false;
	}

	quic_initialze_arrays();
	if (!quic_parse_headers(pkt, false)) {
		return false;
	}
	return true;
}

bool QUICParser::quic_parse_initial(
	const Packet& pkt,
	const uint8_t* payload_pointer,
	uint64_t offset)
{
	if (!quic_create_initial_secrets()) {
		DEBUG_MSG("Error, creation of initial secrets failed (client side)\n");
		return false;
	}
	if (!quic_decrypt_initial_header(payload_pointer, offset)) {
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

	// 1 if CH or SH parsed
	parsed_initial = 1;

	// According to RFC 9000 the server port will not change.
	if (!quic_set_server_port(pkt)) {
		DEBUG_MSG("Error, extracting server port");
		return false;
	}

	if (tls_hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
		parsed_client_hello = true;
	}

	return true;
}

} // namespace ipxp
