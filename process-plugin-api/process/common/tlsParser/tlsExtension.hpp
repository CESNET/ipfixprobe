#pragma once

#include <cstdint>
#include <span>

#include "tlsExtensionType.hpp"

namespace ipxp
{
    
struct TLSExtension {
    TLSExtensionType type;
    std::span<const std::byte> payload;
};

} // namespace ipxp
