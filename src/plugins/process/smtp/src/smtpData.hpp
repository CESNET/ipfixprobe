#pragma once

#include <boost/static_string.hpp>

namespace ipxp {

struct SMTPData {
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

} // namespace ipxp
