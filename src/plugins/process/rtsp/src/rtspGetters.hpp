/**
 * @file rtspGetters.hpp
 * @brief Getters for RTSP plugin fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "rtspContext.hpp"

#include <utils/stringViewUtils.hpp>

namespace ipxp::process::rtsp {

inline constexpr const RTSPContext& asRTSPContext(const void* context) noexcept
{
	return *static_cast<const RTSPContext*>(context);
}

// RTSPField::RTSP_REQUEST_METHOD
inline constexpr auto getRTSPRequestMethodField
	= [](const void* context) { return toStringView(asRTSPContext(context).method); };

// RTSPField::RTSP_REQUEST_AGENT
inline constexpr auto getRTSPRequestAgentField
	= [](const void* context) { return toStringView(asRTSPContext(context).userAgent); };

// RTSPField::RTSP_REQUEST_URI
inline constexpr auto getRTSPRequestURIField
	= [](const void* context) { return toStringView(asRTSPContext(context).uri); };

// RTSPField::RTSP_RESPONSE_STATUS_CODE
inline constexpr auto getRTSPResponseStatusCodeField
	= [](const void* context) { return asRTSPContext(context).code; };

// RTSPField::RTSP_RESPONSE_SERVER
inline constexpr auto getRTSPResponseServerField
	= [](const void* context) { return toStringView(asRTSPContext(context).server); };

// RTSPField::RTSP_RESPONSE_CONTENT_TYPE
inline constexpr auto getRTSPResponseContentTypeField
	= [](const void* context) { return toStringView(asRTSPContext(context).contentType); };

} // namespace ipxp::process::rtsp