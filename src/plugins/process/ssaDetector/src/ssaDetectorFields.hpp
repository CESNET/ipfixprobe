/**
 * @file ssaDetectorFields.hpp
 * @brief Definition of SSADetectorFields enum for SSA Detector plugin.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::ssaDetector {

/**
 * @enum SSADetectorFields
 * @brief Enumerates the fields exported by the SSADetector plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class SSADetectorFields : std::size_t {
	SSA_CONF_LEVEL = 0,
	FIELDS_SIZE,
};

} // namespace ipxp::process::ssaDetector
