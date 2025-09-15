#pragma once

#include <cstdint>

enum class WireguardPacketType : uint8_t {
	HANDSHAKE_INIT = 0x01,
	HANDSHAKE_RESPONSE = 0x02,
	COOCKIE_REPLY = 0x03,
	TRANSPORT_DATA = 0x04
};