#pragma once

#include <cstddef>

namespace ipxp
{

enum class RTSPFields : std::size_t {
	RTSP_REQUEST_METHOD = 0,
	RTSP_REQUEST_AGENT,
	RTSP_REQUEST_URI,
	RTSP_RESPONSE_STATUS_CODE,
	RTSP_RESPONSE_SERVER,
	RTSP_RESPONSE_CONTENT_TYPE,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
