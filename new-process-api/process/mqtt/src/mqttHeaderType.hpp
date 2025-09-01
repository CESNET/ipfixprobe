#pragma once

#include <cstdint>

namespace ipxp {

enum class MQTTHeaderType : uint8_t {
    CONNECT = 1,
    CONNECT_ACK,
    PUBLISH,
    DISCONNECT = 14,
};

} // namespace ipxp 
