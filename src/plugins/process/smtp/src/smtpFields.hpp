/**
 * @file
 * @brief Definition of SMTP fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp::process::smtp {

/**
 * @enum SMTPFields
 * @brief Enumerates the fields exported by the SMTP plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class SMTPFields : std::size_t {
	SMTP_2XX_STAT_CODE_COUNT = 0,
	SMTP_3XX_STAT_CODE_COUNT,
	SMTP_4XX_STAT_CODE_COUNT,
	SMTP_5XX_STAT_CODE_COUNT,
	SMTP_COMMAND_FLAGS,
	SMTP_MAIL_CMD_COUNT,
	SMTP_RCPT_CMD_COUNT,
	SMTP_STAT_CODE_FLAGS,
	SMTP_DOMAIN,
	SMTP_FIRST_RECIPIENT,
	SMTP_FIRST_SENDER,
	FIELDS_SIZE,
};

} // namespace ipxp::process::smtp
