/**
 * @file httpGetters.hpp
 * @brief Getters for HTTP plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "httpContext.hpp"

#include <utils/stringViewUtils.hpp>

namespace ipxp::process::http {

inline constexpr const HTTPContext& asHTTPContext(const void* context) noexcept
{
	return *static_cast<const HTTPContext*>(context);
}

// HTTPField::HTTP_REQUEST_METHOD
inline constexpr auto getHTTPMethodField
	= [](const void* context) { return toStringView(asHTTPContext(context).method); };

// HTTPField::HTTP_REQUEST_HOST
inline constexpr auto getHTTPHostField
	= [](const void* context) { return toStringView(asHTTPContext(context).host); };

// HTTPField::HTTP_REQUEST_URL
inline constexpr auto getHTTPURLField
	= [](const void* context) { return toStringView(asHTTPContext(context).uri); };

// HTTPField::HTTP_REQUEST_AGENT
inline constexpr auto getHTTPUserAgentField
	= [](const void* context) { return toStringView(asHTTPContext(context).userAgent); };

// HTTPField::HTTP_REQUEST_REFERER
inline constexpr auto getHTTPRefererField
	= [](const void* context) { return toStringView(asHTTPContext(context).referer); };

// HTTPField::HTTP_RESPONSE_STATUS_CODE
inline constexpr auto getHTTPStatusCodeField
	= [](const void* context) { return asHTTPContext(context).statusCode; };

// HTTPField::HTTP_RESPONSE_CONTENT_TYPE
inline constexpr auto getHTTPContentTypeField
	= [](const void* context) { return toStringView(asHTTPContext(context).contentType); };

// HTTPField::HTTP_RESPONSE_SERVER
inline constexpr auto getHTTPServerField
	= [](const void* context) { return toStringView(asHTTPContext(context).server); };

// HTTPField::HTTP_RESPONSE_SET_COOKIE_NAMES
inline constexpr auto getHTTPCookiesField
	= [](const void* context) { return toStringView(asHTTPContext(context).cookies); };

} // namespace ipxp::process::http