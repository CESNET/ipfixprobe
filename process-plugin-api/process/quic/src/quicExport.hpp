#pragma once

#include <array>
#include <optional>
#include <span>
#include <boost/static_string.hpp>
#include <boost/container/static_vector.hpp>


#include "burst.hpp"

namespace ipxp
{

struct QUICExport {
	constexpr static std::size_t BUFFER_SIZE = 255;
	constexpr static std::size_t MAX_CONNECTION_ID_LENGTH = 20;
	constexpr static std::size_t MAX_PACKETS = 30;
	constexpr static std::size_t MAX_TLS_EXTENSIONS = 30;
	constexpr static std::size_t MAX_BUFFER_SIZE = 1500;

	boost::static_string<BUFFER_SIZE> sni;
	boost::static_string<BUFFER_SIZE> userAgent;
	uint32_t quicVersion;
	uint32_t quicClientVersion;
	uint64_t quicTokenLength;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> originalClientId;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> originalServerId;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> serverId;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> retryScid;
	uint8_t multiplexedCount;
	uint8_t quicZeroRTTCount;
	uint8_t clientHelloParsed;
	uint16_t serverPort;
	boost::container::static_vector<uint8_t, MAX_PACKETS> packetTypes;
	boost::container::static_vector<uint16_t, MAX_TLS_EXTENSIONS> tlsExtensionTypes;
	boost::container::static_vector<uint16_t, MAX_TLS_EXTENSIONS> tlsExtensionLengths;
	boost::container::static_vector<std::byte, MAX_BUFFER_SIZE> extensionsPayload;



	// We use a char as a buffer.
	uint8_t occidLength;
	uint8_t oscidLength;
	uint8_t scidLength;
	//uint8_t initial_dcid_length;
	
	boost::static_string<MAX_CONNECTION_ID_LENGTH> initialDestConnectionId;
	// Intermediate storage when direction is not clear
	boost::static_string<MAX_CONNECTION_ID_LENGTH> dirScid;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> dirDcid;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> dirScid2;
	boost::static_string<MAX_CONNECTION_ID_LENGTH> dirDcid2;
	uint16_t dirDport;
	uint16_t dirDport2;
	uint8_t cntRetryPackets;



	
	uint16_t tls_ext_type_len;
	bool tls_ext_type_set;

	uint8_t tls_ext_len_len;
	bool tls_ext_len_set;

	uint16_t tls_ext_length;
	bool tls_ext_set;

	uint8_t last_pkt_type;


	// Flags to ease decisions
	bool occid_set;
	bool oscid_set;
	bool scid_set;

	bool client_version_set;
	bool client_hello_seen;
	bool packet_from_server_seen;
};  

} // namespace ipxp

