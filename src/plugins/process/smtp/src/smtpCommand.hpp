/**
 * @file
 * @brief Definition of SMTP commands.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>

namespace ipxp::process::smtp {

/**
 * @enum SMTPCommand
 * @brief Enumerates SMTP commands used in command flags.
 */
enum SMTPCommand : uint16_t {
	EHLO = 0x0001,
	HELO = 0x0002,
	MAIL = 0x0004,
	RCPT = 0x0008,
	DATA = 0x0010,
	RSET = 0x0020,
	VRFY = 0x0040,
	EXPN = 0x0080,
	HELP = 0x0100,
	NOOP = 0x0200,
	QUIT = 0x0400,
	UNKNOWN = 0x8000
};

} // namespace ipxp::process::smtp
