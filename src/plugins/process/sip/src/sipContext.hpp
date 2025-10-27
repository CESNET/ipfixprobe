/**
 * @file
 * @brief Export data of SIP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <boost/static_string.hpp>

namespace ipxp::process::sip {

/**
 * @struct SIPContext
 * @brief Stores parsed SIP data that will be exported.
 */
struct SIPContext {
	constexpr static std::size_t MAX_SIZE = 128;

	uint16_t
		messageType; /* SIP message code (register, invite) < 100 or SIP response status > 100 */
	uint16_t statusCode;
	boost::static_string<MAX_SIZE> callId; /* Call id. For sevice SIP traffic call id = 0 */
	boost::static_string<MAX_SIZE> callingParty; /* Calling party (ie. from) uri */
	boost::static_string<MAX_SIZE> calledParty; /* Called party (ie. to) uri */
	boost::static_string<MAX_SIZE> via; /* Via field of SIP packet */
	boost::static_string<MAX_SIZE> userAgent; /* User-Agent field of SIP packet */
	boost::static_string<MAX_SIZE> commandSequence; /* CSeq field of SIP packet */
	boost::static_string<MAX_SIZE> requestURI; /* Request-URI of SIP request */
};

} // namespace ipxp::process::sip
