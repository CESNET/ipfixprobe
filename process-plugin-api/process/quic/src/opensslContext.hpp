#pragma once

#include <openssl/evp.h>
#include <memory>

namespace ipxp
{

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

auto createCipherContext = []() -> CipherContext {
    return CipherContext(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
};

auto createKeyContext = []() -> KeyContext {
    return KeyContext(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
};

} // namespace ipxp
