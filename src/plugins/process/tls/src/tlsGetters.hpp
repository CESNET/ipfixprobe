
/**
 * @file tlsGetters.hpp
 * @brief Getters for TLS plugin fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "tlsContext.hpp"

#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::tls {

inline constexpr const TLSContext& asTLSContext(const void* context) noexcept
{
	return *static_cast<const TLSContext*>(context);
}

// TLSField::TLS_SNI
inline constexpr auto getTLSSNIField
	= [](const void* context) { return toStringView(asTLSContext(context).serverNames); };

// TLSField::TLS_JA3
inline constexpr auto getTLSJA3Field
	= [](const void* context) { return toSpan<const char>(asTLSContext(context).ja3); };

// TLSField::TLS_JA4
inline constexpr auto getTLSJA4Field
	= [](const void* context) { return toStringView(asTLSContext(context).ja4); };

// TLSField::TLS_ALPN
inline constexpr auto getTLSALPNField
	= [](const void* context) { return toStringView(asTLSContext(context).serverALPNs); };

// TLSField::TLS_VERSION
inline constexpr auto getTLSVersionField
	= [](const void* context) { return asTLSContext(context).version; };

// TLSField::TLS_EXT_TYPE
inline constexpr auto getTLSExtensionTypesField = [](const void* context) {
	return toSpan<const uint16_t>(asTLSContext(context).extensionTypes);
};

// TLSField::TLS_EXT_LEN
inline constexpr auto getTLSExtensionLengthsField = [](const void* context) {
	return toSpan<const uint16_t>(asTLSContext(context).extensionLengths);
};

} // namespace ipxp::process::tls
