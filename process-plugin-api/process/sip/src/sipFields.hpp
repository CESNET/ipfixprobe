#pragma once

#include <cstddef>

namespace ipxp
{

enum class SIPFields : std::size_t {
	SIP_MSG_TYPE = 0,
	SIP_STATUS_CODE,
	SIP_CSEQ,
	SIP_CALLING_PARTY,
	SIP_CALLED_PARTY,
	SIP_CALL_ID,
	SIP_USER_AGENT,
	SIP_REQUEST_URI,
	SIP_VIA,
	FIELDS_SIZE,
};    
    
} // namespace ipxp
