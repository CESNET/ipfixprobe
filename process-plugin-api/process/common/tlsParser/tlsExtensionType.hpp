#pragma once

#include <cstdint>

namespace ipxp
{
    
enum class TLSExtensionType : uint16_t
{
    SERVER_NAME = 0,
    SUPPORTED_GROUPS = 10, // AKA supported_groups, ECLIPTIC_CURVES
    ELLIPTIC_CURVE_POINT_FORMATS = 11,
    SIGNATURE_ALGORITHMS = 13,
    ALPN = 16,
    SUPPORTED_VERSION = 43
}

} // namespace ipxp::tls
