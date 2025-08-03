#pragma once

#include <cstdint>

#include "mqttHeaderType.hpp"

namespace ipxp {

union MQTTTypeFlag {

    MQTTTypeFlag(const uint8_t raw) noexcept
    : raw(raw) {}

    struct {
        MQTTHeaderType type : 4;
        uint8_t flag : 4;
    } bitfields;

    uint8_t raw;
};

static_assert(sizeof(MQTTTypeFlag) == 1, "Unexpected MQTTTypeFlag size");

} // namespace ipxp