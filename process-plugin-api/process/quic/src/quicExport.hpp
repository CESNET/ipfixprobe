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
	boost::static_string<BUFFER_SIZE> userAgent;
	uint32_t quicVersion;
	uint32_t quicClientVersion;
	uint64_t quicTokenLength;
	// We use a char as a buffer.
	uint8_t occidLength;
	uint8_t oscidLength;
	uint8_t scidLength;
	//uint8_t initial_dcid_length;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> occid;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> oscid;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> scid;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> initialDestConnectionId;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> retryScid;
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

