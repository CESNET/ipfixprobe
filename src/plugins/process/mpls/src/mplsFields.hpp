/**
 * @file
 * @brief Export fields of MPLS plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::mpls {

/**
 * @enum MPLSFields
 * @brief Enumerates the fields exported by the MPLS plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class MPLSFields : std::size_t {
	MPLS_TOP_LABEL_STACK_SECTION = 0,
	FIELDS_SIZE,
};

} // namespace ipxp::process::mpls
