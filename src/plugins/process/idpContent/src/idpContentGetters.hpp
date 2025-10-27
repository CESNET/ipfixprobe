/**
 * @file idpContentGetters.hpp
 * @brief Getters for IDPContent plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "idpContentContext.hpp"

#include <utils/spanUtils.hpp>

namespace ipxp::process::idpContent {

inline constexpr const IDPContentContext& asIDPContentContext(const void* context)
{
	return *reinterpret_cast<const IDPContentContext*>(context);
}

inline constexpr auto getIDPContentField = [](const void* context, const Direction direction) {
	return toSpan<const std::byte>(*asIDPContentContext(context).directionalContent[direction]);
};

} // namespace ipxp::process::idpContent