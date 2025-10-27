
/**
 * @file ssaDetectorGetters.hpp
 * @brief Getters for SSA Detector plugin fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "ssaDetectorContext.hpp"

#include <utils/spanUtils.hpp>

namespace ipxp::process::ssaDetector {

inline constexpr const SSADetectorContext& asSSADetectorContext(const void* context) noexcept
{
	return *static_cast<const SSADetectorContext*>(context);
}

// SSADetectorField::SSA_CONF_LEVEL
inline constexpr auto getSSAConfLevelField
	= [](const void* context) { return asSSADetectorContext(context).confidence; };

} // namespace ipxp::process::ssaDetector
