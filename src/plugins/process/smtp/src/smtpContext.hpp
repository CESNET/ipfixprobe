/**
 * @file
 * @brief Export data of SMTP plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <boost/static_string.hpp>

namespace ipxp::process::smtp {

/**
 * @struct SMTPContext
 * @brief Stores parsed SMTP data that will be exported.
 */
struct SMTPContext {
	constexpr static std::size_t MAX_STRING_LENGTH = 255;

	uint32_t codeCount2xx;
	uint32_t codeCount3xx;
	uint32_t codeCount4xx;
	uint32_t codeCount5xx;
	uint32_t commandFlags;
	uint32_t mailCommandCount;
	uint32_t mailRecipientCount;
	uint32_t mailCodeFlags;
	boost::static_string<MAX_STRING_LENGTH> domain;
	boost::static_string<MAX_STRING_LENGTH> firstSender;
	boost::static_string<MAX_STRING_LENGTH> firstRecipient;

	struct {
		bool isDataTransfer {false};
	} processingState;
};

} // namespace ipxp::process::smtp
