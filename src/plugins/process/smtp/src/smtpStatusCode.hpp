/**
 * @file
 * @brief Definition of SMTP status codes.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */
#pragma once

#include <cstddef>

namespace ipxp::process::smtp {

/**
 * @enum SMTPStatusCode
 * @brief Enumerates SMTP status codes used in status code cumulative.
 */
enum SMTPStatusCode : std::size_t {
	STATUS_CODE_211 = 0x00000001,
	STATUS_CODE_214 = 0x00000002,
	STATUS_CODE_220 = 0x00000004,
	STATUS_CODE_221 = 0x00000008,
	STATUS_CODE_250 = 0x00000010,
	STATUS_CODE_251 = 0x00000020,
	STATUS_CODE_252 = 0x00000040,
	STATUS_CODE_354 = 0x00000080,
	STATUS_CODE_421 = 0x00000100,
	STATUS_CODE_450 = 0x00000200,
	STATUS_CODE_451 = 0x00000400,
	STATUS_CODE_452 = 0x00000800,
	STATUS_CODE_455 = 0x00001000,
	STATUS_CODE_500 = 0x00002000,
	STATUS_CODE_501 = 0x00004000,
	STATUS_CODE_502 = 0x00008000,
	STATUS_CODE_503 = 0x00010000,
	STATUS_CODE_504 = 0x00020000,
	STATUS_CODE_550 = 0x00040000,
	STATUS_CODE_551 = 0x00080000,
	STATUS_CODE_552 = 0x00100000,
	STATUS_CODE_553 = 0x00200000,
	STATUS_CODE_554 = 0x00400000,
	STATUS_CODE_555 = 0x00800000,
	STATUS_CODE_SPAM = 0x40000000, // indicates that answer contains SPAM keyword
	STATUS_CODE_UNKNOWN = 0x80000000
};

} // namespace ipxp::process::smtp
