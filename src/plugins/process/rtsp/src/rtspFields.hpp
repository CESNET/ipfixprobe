/**
 * @file
 * @brief Export fields of RTSP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::rtsp {

/**
 * @enum RTSPFields
 * @brief Enumerates the fields exported by the RTSP plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class RTSPFields : std::size_t {
	RTSP_REQUEST_METHOD = 0,
	RTSP_REQUEST_AGENT,
	RTSP_REQUEST_URI,
	RTSP_RESPONSE_STATUS_CODE,
	RTSP_RESPONSE_SERVER,
	RTSP_RESPONSE_CONTENT_TYPE,
	FIELDS_SIZE,
};

} // namespace ipxp::process::rtsp
