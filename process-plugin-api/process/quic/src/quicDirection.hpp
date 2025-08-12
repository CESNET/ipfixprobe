#pragma once

#include <cstdint>

#include <directionalField.hpp>

namespace ipxp
{
enum class QUICDirection : uint8_t {
    CLIENT_TO_SERVER = static_cast<uint8_t>(Direction::Forward),
    SERVER_TO_CLIENT = static_cast<uint8_t>(Direction::Reverse),
};

} // namespace ipxp
