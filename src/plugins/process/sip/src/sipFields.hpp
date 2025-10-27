/**
 * @file
 * @brief Export fields of SIP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::sip {

/**
 * @enum SIPFields
 * @brief Enumerates the fields exported by the SIP plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
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

} // namespace ipxp::process::sip
