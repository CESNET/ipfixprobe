#pragma once

#include <array>
#include <cstdint>

namespace ipxp::process::quic {

struct QUICInitialSecrets {
	constexpr static std::size_t TLS13_AEAD_NONCE_LENGTH = 12;
	constexpr static std::size_t AES_128_KEY_LENGTH = 16;

	std::array<std::byte, AES_128_KEY_LENGTH> key;
	std::array<std::byte, TLS13_AEAD_NONCE_LENGTH> initialVector;
	std::array<std::byte, AES_128_KEY_LENGTH> headerProtection;
};

} // namespace ipxp