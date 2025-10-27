/**
 * @file smtpGetters.hpp
 * @brief Getters for SMTP plugin fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "smtpContext.hpp"

#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::smtp {

inline constexpr const SMTPContext& asSMTPContext(const void* context) noexcept
{
	return *static_cast<const SMTPContext*>(context);
}

// SMTPField::SMTP_2XX_STAT_CODE_COUNT
inline constexpr auto getSMTP2xxStatCodeCountField
	= [](const void* context) { return asSMTPContext(context).codeCount2xx; };

// SMTPField::SMTP_3XX_STAT_CODE_COUNT
inline constexpr auto getSMTP3xxStatCodeCountField
	= [](const void* context) { return asSMTPContext(context).codeCount3xx; };

// SMTPField::SMTP_4XX_STAT_CODE_COUNT
inline constexpr auto getSMTP4xxStatCodeCountField
	= [](const void* context) { return asSMTPContext(context).codeCount4xx; };

// SMTPField::SMTP_5XX_STAT_CODE_COUNT
inline constexpr auto getSMTP5xxStatCodeCountField
	= [](const void* context) { return asSMTPContext(context).codeCount5xx; };

// SMTPField::SMTP_COMMAND_FLAGS
inline constexpr auto getSMTPCommandFlagsField
	= [](const void* context) { return asSMTPContext(context).commandFlags; };

// SMTPField::SMTP_MAIL_CMD_COUNT
inline constexpr auto getSMTPMailCmdCountField
	= [](const void* context) { return asSMTPContext(context).mailCommandCount; };

// SMTPField::SMTP_RCPT_CMD_COUNT
inline constexpr auto getSMTPRcptCmdCountField
	= [](const void* context) { return asSMTPContext(context).mailRecipientCount; };

// SMTPField::SMTP_STAT_CODE_FLAGS
inline constexpr auto getSMTPStatCodeFlagsField
	= [](const void* context) { return asSMTPContext(context).mailCodeFlags; };

// SMTPField::SMTP_DOMAIN
inline constexpr auto getSMTPDomainField
	= [](const void* context) { return toStringView(asSMTPContext(context).domain); };

// SMTPField::SMTP_FIRST_RECIPIENT
inline constexpr auto getSMTPFirstRecipientField
	= [](const void* context) { return toStringView(asSMTPContext(context).firstRecipient); };

// SMTPField::SMTP_FIRST_SENDER
inline constexpr auto getSMTPFirstSenderField
	= [](const void* context) { return toStringView(asSMTPContext(context).firstSender); };

} // namespace ipxp::process::smtp