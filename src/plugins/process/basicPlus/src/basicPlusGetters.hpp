/**
 * @file basicPlusGetters.hpp
 * @brief Getters for BasicPlus plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "basicPlusContext.hpp"

namespace ipxp::process::basicPlus {

inline const BasicPlusContext& asBasicPlusContext(const void* context) noexcept
{
	return *static_cast<const BasicPlusContext*>(context);
}

// BasicPlusField::IPTTL
inline constexpr auto getIPTTLField = [](const void* context, const Direction direction) {
	return asBasicPlusContext(context).ipTTL[direction];
};

// BasicPlusField::IPFlag
inline constexpr auto getIPFlagField = [](const void* context, const Direction direction) {
	return asBasicPlusContext(context).ipFlag[direction];
};

// BasicPlusField::TCPWindow
inline constexpr auto getTCPWindowField = [](const void* context, const Direction direction) {
	return asBasicPlusContext(context).tcpWindow[direction];
};

// BasicPlusField::TCPOption
inline constexpr auto getTCPOptionField = [](const void* context, const Direction direction) {
	return asBasicPlusContext(context).tcpOption[direction];
};

// BasicPlusField::TCPMSS
inline constexpr auto getTCPMSSField = [](const void* context, const Direction direction) {
	return asBasicPlusContext(context).tcpMSS[direction];
};

// BasicPlusField::TCPSynSize
inline constexpr auto getTCPSynSizeField
	= [](const void* context) { return asBasicPlusContext(context).tcpSynSize; };

} // namespace ipxp::process::basicPlus
