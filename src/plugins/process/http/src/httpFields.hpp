/**
 * @file
 * @brief Export fields of HTTP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::http {

/**
 * @enum HTTPFields
 * @brief Enumerates the fields exported by the HTTP plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class HTTPFields : std::size_t {
	HTTP_REQUEST_METHOD = 0,
	HTTP_REQUEST_HOST,
	HTTP_REQUEST_URL,
	HTTP_REQUEST_AGENT,
	HTTP_REQUEST_REFERER,
	HTTP_RESPONSE_STATUS_CODE,
	HTTP_RESPONSE_CONTENT_TYPE,
	HTTP_RESPONSE_SERVER,
	HTTP_RESPONSE_SET_COOKIE_NAMES,
	FIELDS_SIZE,
};

} // namespace ipxp::process::http
