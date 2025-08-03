#pragma once

#include <array>
#include <optional>
#include <span>
#include <boost/static_string/static_string.hpp>


#include "burst.hpp"

namespace ipxp
{

struct QUICExport {
	constexpr static std::size_t BUFFER_SIZE = 255;
	constexpr static std::size_t MAX_CONNECTION_ID_LENGTH = 20;

	boost::static_string<BUFFER_SIZE> sni;
	boost::static_string<BUFFER_SIZE> user_agent;
	uint32_t quic_version;
	uint32_t quic_client_version;
	uint64_t quic_token_length;
	// We use a char as a buffer.
	uint8_t occid_length;
	uint8_t oscid_length;
	uint8_t scid_length;
	//uint8_t initial_dcid_length;
	uint8_t dir_scid_length;
	uint8_t dir_dcid_length;
	uint8_t dir_scid_length2;
	uint8_t dir_dcid_length2;
	uint8_t retry_scid_length;
	char occid[MAX_CONNECTION_ID_LENGTH] = {0};
	char oscid[MAX_CONNECTION_ID_LENGTH] = {0};
	char scid[MAX_CONNECTION_ID_LENGTH] = {0};
	boost::static_string<MAX_CONNECTION_ID_LENGTH> initialDestConnectionId;
	char retry_scid[MAX_CONNECTION_ID_LENGTH] = {0};
	// Intermediate storage when direction is not clear
	char dir_scid[MAX_CONNECTION_ID_LENGTH] = {0};
	char dir_dcid[MAX_CONNECTION_ID_LENGTH] = {0};
	char dir_scid2[MAX_CONNECTION_ID_LENGTH] = {0};
	char dir_dcid2[MAX_CONNECTION_ID_LENGTH] = {0};
	uint16_t dir_dport;
	uint16_t dir_dport2;
	uint16_t server_port;
	uint8_t cnt_retry_packets;

	uint8_t quic_multiplexed;
	uint8_t quic_zero_rtt;
	uint8_t pkt_types[QUIC_MAX_ELEMCOUNT];

	uint16_t tls_ext_type[MAX_QUIC_TLS_EXT_LEN];
	uint16_t tls_ext_type_len;
	bool tls_ext_type_set;

	uint16_t tls_ext_len[MAX_QUIC_TLS_EXT_LEN];
	uint8_t tls_ext_len_len;
	bool tls_ext_len_set;

	char tls_ext[CURRENT_BUFFER_SIZE];
	uint16_t tls_ext_length;
	bool tls_ext_set;

	uint8_t last_pkt_type;

	uint8_t parsed_ch;

	// Flags to ease decisions
	bool occid_set;
	bool oscid_set;
	bool scid_set;

	bool client_version_set;
	bool client_hello_seen;
	bool packet_from_server_seen;
};  

} // namespace ipxp

