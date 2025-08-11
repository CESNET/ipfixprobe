#pragma once

#include <cstddef>

enum class WireguardPacketSize : std::size_t {
	HANDSHAKE_INIT_SIZE = 148,
	HANDSHAKE_RESPONSE_SIZE = 92,
	COOKIE_REPLY_SIZE = 64,
	MIN_TRANSPORT_DATA_SIZE = 32
};