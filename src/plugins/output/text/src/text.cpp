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

#include "text.hpp"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <string>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

static const PluginManifest textPluginManifest = {
	.name = "text",
	.description = "Output plugin for text export",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			TextOptParser parser;
			parser.usage(std::cout);
		},
};

TextExporter::TextExporter(const std::string& params, ProcessPlugins& plugins)
	: m_out(&std::cout)
	, m_hide_mac(false)
{
	init(params.c_str());
	(void) plugins;
}

TextExporter::~TextExporter()
{
	close();
}

void TextExporter::init(const char* params)
{
	TextOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	if (parser.m_to_file) {
		std::ofstream* file = new std::ofstream(parser.m_file, std::ofstream::out);
		if (file->fail()) {
			throw PluginError("failed to open output file");
		}
		m_out = file;
	}
	m_hide_mac = parser.m_hide_mac;

	if (!m_hide_mac) {
		*m_out << "mac ";
	}
	*m_out << "conversation packets bytes tcp-flags time extensions" << std::endl;
}

void TextExporter::init(const char* params, ProcessPlugins& plugins)
{
	(void) plugins;
	init(params);
}

void TextExporter::close()
{
	if (m_out != &std::cout) {
		delete m_out;
		m_out = &std::cout;
	}
}

int TextExporter::export_flow(const Flow& flow)
{
	RecordExt* ext = flow.m_exts;

	m_flows_seen++;
	print_basic_flow(flow);
	while (ext != nullptr) {
		*m_out << " " << ext->get_text();
		ext = ext->m_next;
	}
	*m_out << std::endl;

	return 0;
}

void TextExporter::print_basic_flow(const Flow& flow)
{
	time_t sec;
	char time_begin[100];
	char time_end[100];
	char src_mac[18];
	char dst_mac[18];
	char tmp[50];
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
	std::string lb = "";
	std::string rb = "";

	sec = flow.time_first.tv_sec;
	strftime(tmp, sizeof(tmp), "%FT%T", localtime(&sec));
	snprintf(time_begin, sizeof(time_begin), "%s.%06ld", tmp, flow.time_first.tv_usec);
	sec = flow.time_last.tv_sec;
	strftime(tmp, sizeof(tmp), "%FT%T", localtime(&sec));
	snprintf(time_end, sizeof(time_end), "%s.%06ld", tmp, flow.time_last.tv_usec);

	const uint8_t* p = const_cast<uint8_t*>(flow.src_mac);
	snprintf(
		src_mac,
		sizeof(src_mac),
		"%02x:%02x:%02x:%02x:%02x:%02x",
		p[0],
		p[1],
		p[2],
		p[3],
		p[4],
		p[5]);
	p = const_cast<uint8_t*>(flow.dst_mac);
	snprintf(
		dst_mac,
		sizeof(dst_mac),
		"%02x:%02x:%02x:%02x:%02x:%02x",
		p[0],
		p[1],
		p[2],
		p[3],
		p[4],
		p[5]);

	if (flow.ip_version == IP::v4) {
		inet_ntop(AF_INET, (const void*) &flow.src_ip.v4, src_ip, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, (const void*) &flow.dst_ip.v4, dst_ip, INET6_ADDRSTRLEN);
	} else if (flow.ip_version == IP::v6) {
		inet_ntop(AF_INET6, (const void*) &flow.src_ip.v6, src_ip, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (const void*) &flow.dst_ip.v6, dst_ip, INET6_ADDRSTRLEN);
		lb = "[";
		rb = "]";
	}

	if (!m_hide_mac) {
		*m_out << src_mac << "->" << dst_mac << " ";
	}
	*m_out << std::setw(2) << static_cast<unsigned>(flow.ip_proto) << "@" << lb << src_ip << rb
		   << ":" << flow.src_port << "->" << lb << dst_ip << rb << ":" << flow.dst_port << " "
		   << flow.src_packets << "->" << flow.dst_packets << " " << flow.src_bytes << "->"
		   << flow.dst_bytes << " " << static_cast<unsigned>(flow.src_tcp_flags) << "->"
		   << static_cast<unsigned>(flow.dst_tcp_flags) << " " << time_begin << "->" << time_end;
}

static const PluginRegistrar<TextExporter, OutputPluginFactory> textRegistrar(textPluginManifest);

} // namespace ipxp
