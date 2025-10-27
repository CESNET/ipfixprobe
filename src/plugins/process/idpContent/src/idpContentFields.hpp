/**
 * @file
 * @brief Export fields of idpcontent plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::idpContent {

/**
 * @enum IDPContentFields
 * @brief Enumerates the fields exported by the IDPContent plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class IDPContentFields : std::size_t {
	IDP_CONTENT = 0,
	IDP_CONTENT_REV,
	FIELDS_SIZE,
};

} // namespace ipxp::process::idpContent
