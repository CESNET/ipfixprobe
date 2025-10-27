#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include <arpa/inet.h>

namespace ipxp {

enum TCPOptionKind : uint8_t {
	EndOfOptionList = 0,
	NoOperation = 1,
	MaximumSegmentSize = 2,
};

struct TCPOptions {
	constexpr static std::optional<TCPOptions>
	createFrom(std::span<const std::byte> options) noexcept
	{
		if (options.empty()) {
			return std::nullopt;
		}

		auto res = std::optional(TCPOptions {});

		do {
			const TCPOptionKind kind = static_cast<TCPOptionKind>(options[0]);
			switch (kind) {
			case TCPOptionKind::EndOfOptionList:
				return res;
			case TCPOptionKind::NoOperation:
				options = options.subspan(1);
				break;
			case TCPOptionKind::MaximumSegmentSize:
				if (options.size() < 4 || static_cast<uint8_t>(options[1]) != 4) {
					return std::nullopt;
				}

				res->mss = ntohs(*reinterpret_cast<const uint16_t*>(&options[2]));
				res->ipfixCumulative |= uint64_t(1) << ((kind & 0xF8) + (0x07 - (kind & 0x07)));
				options = options.subspan(4);
				break;
			default:
				if (options.size() < 2) {
					return std::nullopt;
				}
				auto len = static_cast<uint8_t>(options[1]);
				if (options.size() < len + 2) {
					return std::nullopt;
				}
				options = options.subspan(len + 2);
				break;
			}
		} while (!options.empty());

		return std::nullopt;
	}

	uint64_t ipfixCumulative {0};
	std::optional<uint16_t> mss {0};

private:
	constexpr TCPOptions() = default;
};

} // namespace ipxp
