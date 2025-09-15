#pragma once

#include <cstddef>

namespace ipxp
{

enum class TLSFields : std::size_t {
	TLS_SNI = 0,
	TLS_JA3,
	TLS_JA4,
	TLS_ALPN,
	TLS_VERSION,
	TLS_EXT_TYPE,
	TLS_EXT_LEN,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
