/**
 * @file mplsGetters.hpp
 * @brief Getters for MPLS plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "mplsContext.hpp"

#include <utils/spanUtils.hpp>

namespace ipxp::process::mpls {

inline constexpr const MPLSContext& asMPLSContext(const void* context) noexcept
{
	return *static_cast<const MPLSContext*>(context);
}

// MPLSField::MPLSTopLabelStackSection
inline constexpr auto getMPLSTopLabelStackSectionField
	= [](const void* context) { return asMPLSContext(context).topLabel; };

} // namespace ipxp::process::mpls
