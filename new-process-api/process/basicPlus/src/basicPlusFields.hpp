#pragma once

#include <cstddef>

namespace ipxp
{

enum class BasicPlusFields : std::size_t {
	IP_TTL = 0,
	IP_TTL_REV,
	IP_FLG,
	IP_FLG_REV,
	TCP_WIN,
	TCP_WIN_REV,
	TCP_OPT,
	TCP_OPT_REV,
	TCP_MSS,
	TCP_MSS_REV,
	TCP_SYN_SIZE,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
