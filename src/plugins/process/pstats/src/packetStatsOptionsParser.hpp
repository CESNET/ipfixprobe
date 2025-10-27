#pragma once

#include <ipfixprobe/options.hpp>

namespace ipxp::process::packet_stats {

class PacketStatsOptionsParser : public OptionsParser {
public:
	bool m_countEmptyPackets;
	bool m_skipDuplicates;

	PacketStatsOptionsParser()
		: OptionsParser("pstats", "Processing plugin for packet stats")
		, m_countEmptyPackets(false)
		, m_skipDuplicates(false)
	{
		register_option(
			"i",
			"includezeroes",
			"",
			"Include zero payload packets",
			[this](const char* arg) {
				(void) arg;
				m_countEmptyPackets = true;
				return true;
			},
			OptionFlags::NoArgument);
		register_option(
			"s",
			"skipdup",
			"",
			"Skip duplicated TCP packets",
			[this](const char* arg) {
				(void) arg;
				m_skipDuplicates = true;
				return true;
			},
			OptionFlags::NoArgument);
	}
};

} // namespace ipxp