#pragma once

#include <ipfixprobe/options.hpp>

namespace ipxp {

class PacketHistogramOptionsParser : public OptionsParser {
public:
	bool m_includeZeroes;

	PacketHistogramOptionsParser()
		: OptionsParser("phists", "Processing plugin for packet histograms")
		, m_includeZeroes(false)
	{
		register_option(
			"i",
			"includezeroes",
			"",
			"Include zero payload packets",
			[this](const char* arg) {
				(void) arg;
				m_includeZeroes = true;
				return true;
			},
			OptionFlags::NoArgument);
	}
};

} // namespace ipxp