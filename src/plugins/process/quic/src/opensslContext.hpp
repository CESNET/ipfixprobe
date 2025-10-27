/**
 * @file
 * @brief Provides OpenSSL wrappers to help maintain lifetime.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <memory>

#include <openssl/evp.h>

namespace ipxp::process::quic {

/**
 * @brief Unique pointer types for OpenSSL cipher contexts with automatic cleanup.
 */
using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

/**
 * @brief Unique pointer type for OpenSSL key context with automatic cleanup.
 */
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

/**
 * @brief Creates a new OpenSSL cipher context with destructor.
 *
 * @return New cipher context.
 */
auto createCipherContext
	= []() -> CipherContext { return CipherContext(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free); };

/**
 * @brief Creates a new KeyContext for HKDF operations using OpenSSL.
 *
 * This lambda function initializes an EVP_PKEY_CTX context for HKDF (HMAC-based Extract-and-Expand
 * Key Derivation Function). The context is wrapped which ensures proper cleanup using
 * EVP_PKEY_CTX_free.
 *
 * @return New key context.
 */
auto createKeyContext = []() -> KeyContext {
	return KeyContext(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
};

} // namespace ipxp::process::quic
