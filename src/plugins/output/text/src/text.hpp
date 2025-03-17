/**
 * @file
 * @brief Prints exported fields
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <string>

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/outputPlugin.hpp>
#include <ipfixprobe/processPlugin.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

class TextOptParser : public OptionsParser {
public:
	std::string m_file;
	bool m_to_file;
	bool m_hide_mac;

	TextOptParser()
		: OptionsParser("text", "Output plugin for text export")
		, m_file("")
		, m_to_file(false)
		, m_hide_mac(false)
	{
		register_option(
			"f",
			"file",
			"PATH",
			"Print output to file",
			[this](const char* arg) {
				m_file = arg;
				m_to_file = true;
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"m",
			"mac",
			"",
			"Hide mac addresses",
			[this](const char* arg) {
				(void) arg;
				m_hide_mac = true;
				return true;
			},
			OptionFlags::NoArgument);
	}
};

class TextExporter : public OutputPlugin {
public:
	TextExporter(const std::string& params, ProcessPlugins& plugins);
	~TextExporter();
	void init(const char* params);
	void init(const char* params, ProcessPlugins& plugins);
	void close();
	OptionsParser* get_parser() const { return new TextOptParser(); }
	std::string get_name() const { return "text"; }
	int export_flow(const Flow& flow);

private:
	std::ostream* m_out;
	bool m_hide_mac;

	void print_basic_flow(const Flow& flow);
};

} // namespace ipxp
