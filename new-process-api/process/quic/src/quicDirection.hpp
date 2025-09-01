#pragma once

#include <cstdint>

#include <directionalField.hpp>

namespace ipxp
{
enum class QUICDirection : uint8_t {
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
};

} // namespace ipxp
