/**
 * @file
 * @brief Definition of SIP message types.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::sip {

/**
 * @enum SIPMessageType
 * @brief Enumerates SIP message types that we are interested in.
 */
enum class SIPMessageType : uint16_t {
	INVITE = 1,
	ACK = 2,
	CANCEL = 3,
	BYE = 4,
	REGISTER = 5,
	OPTIONS = 6,
	PUBLISH = 7,
	NOTIFY = 8,
	INFO = 9,
	SUBSCRIBE = 10,
	REPLY = 99,
	TRYING = 100,
	DIAL_ESTABL = 101,
	RINGING = 180,
	SESSION_PROGR = 183,
	OK = 200,
	BAD_REQ = 400,
	UNAUTHORIZED = 401,
	FORBIDDEN = 403,
	NOT_FOUND = 404,
	PROXY_AUT_REQ = 407,
	BUSY_HERE = 486,
	REQ_CANCELED = 487,
	INTERNAL_ERR = 500,
	DECLINE = 603,
	UNDEFINED = 999
};

} // namespace ipxp::process::sip
