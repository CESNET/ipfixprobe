#pragma once

#include <span>

namespace ipxp {

class QUICSecondaryHeaderParser {
	constexpr SecondaryHeaderParser(std::span<const std::byte> payload, auto&&) noexcept
};

} // namespace ipxp
