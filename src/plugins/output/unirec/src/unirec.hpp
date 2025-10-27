/**
 * @file
 * @brief Flow exporter converting flows to UniRec and sending them to TRAP ifc
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Vaclav Bartos <bartos@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <map>
#include <string>
#include <vector>

//#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/outputPlugin/outputPlugin.hpp>
#include <processPlugin.hpp>
#include <ipfixprobe/utils.hpp>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

namespace ipxp {

class UnirecOptParser : public OptionsParser {
public:
	typedef std::map<unsigned, std::vector<std::string>> IfcPluginMap;

	std::string m_ifc;
	IfcPluginMap m_ifc_map;
	bool m_odid;
	bool m_eof;
	bool m_help;
	uint64_t m_id;
	uint8_t m_dir;
	int m_verbose;

	UnirecOptParser()
		: OptionsParser("unirec", "Output plugin for unirec export")
		, m_ifc("")
		, m_odid(false)
		, m_eof(false)
		, m_help(false)
		, m_id(OutputPlugin::DEFAULT_EXPORTER_ID)
		, m_dir(0)
		, m_verbose(0)
	{
		register_option(
			"i",
			"ifc",
			"SPEC",
			"libtrap interface specifier",
			[this](const char* arg) {
				(void) arg;
				m_ifc = arg;
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"p",
			"plugins",
			"PLUGINS",
			"Specify plugin-interface mapping. Plugins can be grouped like '(p1,p2,p3),p4,(p5,p6)'",
			[this](const char* arg) {
				(void) arg;
				try {
					m_ifc_map = parse_ifc_map(arg);
				} catch (ParserError& e) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"o",
			"odid",
			"",
			"Export ODID field",
			[this](const char* arg) {
				(void) arg;
				m_odid = true;
				return true;
			},
			OptionFlags::NoArgument);
		register_option(
			"e",
			"eof",
			"",
			"Send EOF message on exit",
			[this](const char* arg) {
				m_eof = true;
				return true;
			},
			OptionFlags::NoArgument);
		register_option(
			"I",
			"id",
			"NUM",
			"Exporter identification number",
			[this](const char* arg) {
				try {
					m_id = str2num<decltype(m_id)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"d",
			"dir",
			"NUM",
			"Dir bit field value",
			[this](const char* arg) {
				try {
					m_dir = str2num<decltype(m_dir)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"h",
			"help",
			"",
			"Print libtrap help",
			[this](const char* arg) {
				m_help = true;
				return true;
			},
			OptionFlags::NoArgument);
		register_option(
			"v",
			"verbose",
			"",
			"Increase verbosity",
			[this](const char* arg) {
				m_verbose++;
				return true;
			},
			OptionFlags::NoArgument);
	}

private:
	std::vector<std::string> parse_plugin_group(const std::string& group)
	{
		std::vector<std::string> plugins;
		size_t first = 0;
		size_t last = 0;
		while (1) {
			last = group.find(",", first);
			std::string plugin
				= group.substr(first, (last == std::string::npos ? group.size() : last) - first);
			trim_str(plugin);

			if (plugin.empty()) {
				throw ParserError("invalid plugin group");
			}

			plugins.push_back(plugin);
			first = last + 1;
			if (last == std::string::npos) {
				break;
			}
		}
		return plugins;
	}

	UnirecOptParser::IfcPluginMap parse_ifc_map(const std::string& plugins)
	{
		UnirecOptParser::IfcPluginMap ifc_map;
		size_t first = 0;
		size_t last = 0;
		size_t group = std::string::npos;
		bool error = false;
		if (plugins.empty()) {
			throw ParserError("invalid interface-plugin mapping");
		}
		while (last != std::string::npos) {
			char c = plugins[last];
			if (c == '(') {
				if (group != std::string::npos) {
					error = true;
					break;
				}
				group = last;
				last++;
			} else if (c == ')') {
				if (group == std::string::npos || first != group) {
					error = true;
					break;
				}
				ifc_map[ifc_map.size()]
					= parse_plugin_group(plugins.substr(group + 1, last - group - 1));
				group = std::string::npos;
				first = plugins.find_first_not_of(" ,\t\n\r", last + 1);
				last = first;
			} else if ((c == ',' && group == std::string::npos) || last == plugins.size()) {
				std::string tmp = plugins.substr(first, last - first);
				ifc_map[ifc_map.size()] = parse_plugin_group(tmp);
				first = plugins.find_first_not_of(" ,\t\n\r", last);
				if (c == ',' && first == std::string::npos) {
					error = true;
					break;
				}
				if (last == plugins.size()) {
					break;
				}
				last = first;
			} else {
				last++;
			}
		}
		if (error || group != std::string::npos) {
			throw ParserError("invalid interface-plugin mapping " + plugins);
		}

		return ifc_map;
	}
};

/**
 * \brief Class for exporting flow records.
 */
class IPXP_API UnirecExporter : public OutputPlugin {
public:

	UnirecExporter(const std::string& params, const FieldManager& manager, const std::vector<ProcessPluginEntry>& plugins)
		: OutputPlugin(manager, plugins)
	{
		//TODO parse parameters
		(void)params;
	}

	//UnirecExporter(const std::string& params, ProcessPlugins& plugins);
	~UnirecExporter();
	void init(const char* params);
	void init(const char* params, const std::vector<ProcessPluginEntry>& plugins);
	void close();
	//OptionsParser* get_parser() const { return new UnirecOptParser(); }
	//std::string get_name() const { return "unirec"; }
	//int export_flow(const Flow& flow);
	
	void processRecord(FlowRecordUniquePtr& flowRecord) override;

private:
	int init_trap(std::string& ifcs, int verbosity);
	void create_tmplt(int ifc_idx, const char* tmplt_str);
	void fill_basic_flow(const FlowRecord& flow, ur_template_t* tmplt_ptr, void* record_ptr);
	void free_unirec_resources();
	void fillFromScalarVariant(const FieldDescriptor& field, const ScalarValueGetter& variant, const void* data, ur_template_t* tmplt_ptr, void* record_ptr) noexcept;
	void fillFromVectorVariant(const FieldDescriptor& field, const VectorValueGetter& variant, const void* data, ur_template_t* tmplt_ptr, void* record_ptr) noexcept;

	int m_basic_idx{-1}; /**< Basic output interface number. */
	size_t m_ext_cnt{0}; /**< Size of ifc map. */
	int* m_ifc_map{nullptr}; /**< Contain extension id (as index) -> output interface number mapping. */
	UnirecOptParser::IfcPluginMap m_group_map; /**< Plugin groups mapping to interface number. */

	ur_template_t** m_tmplts{nullptr}; /**< Pointer to unirec templates. */
	void** m_records{nullptr}; /**< Pointer to unirec records. */
	size_t m_ifc_cnt{0}; /**< Number of output interfaces. */
	int* m_ext_id_flgs{nullptr}; /** flags of used extension during export*/
	std::vector<ur_field_id_t> m_field_ids; 

	bool m_eof{false}; /**< Send eof when module exits. */
	bool m_odid{false}; /**< Export ODID field instead of LINK_BIT_FIELD. */
	uint64_t m_link_bit_field{0}; /**< Link bit field value. */
	uint8_t m_dir_bit_field{0}; /**< Direction bit field value. */
};

} // namespace ipxp
