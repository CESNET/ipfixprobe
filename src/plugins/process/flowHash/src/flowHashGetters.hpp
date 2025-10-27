/**
 * @file flowHashGetters.hpp
 * @brief Getters for FlowHash plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "flowHashContext.hpp"

namespace ipxp::process::flowHash {

inline constexpr const FlowHashContext& asFlowHashContext(const void* context) noexcept
{
	return *static_cast<const FlowHashContext*>(context);
}

// FlowHashField::FLOW_ID
inline constexpr auto getFlowIdField
	= [](const void* context) { return asFlowHashContext(context).flowHash; };

} // namespace ipxp::process::flowHash
