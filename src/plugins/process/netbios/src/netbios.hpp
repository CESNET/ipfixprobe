/**
 * @file
 * @brief Plugin for parsing netbios traffic.
 * @author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstring>
#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <dns-utils.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/processPlugin.hpp>

namespace ipxp {

#define NETBIOS_UNIREC_TEMPLATE "NB_NAME,NB_SUFFIX"

UR_FIELDS(string NB_NAME, uint8 NB_SUFFIX)

/**
 * \brief Flow record extension header for storing parsed NETBIOS packets.
 */
struct RecordExtNETBIOS : public RecordExt {
	static int REGISTERED_ID;

	std::string netbios_name;
	char netbios_suffix;

	RecordExtNETBIOS()
		: RecordExt(REGISTERED_ID)
		, netbios_suffix(0)
	{
	}

#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_NB_SUFFIX, netbios_suffix);
		ur_set_string(tmplt, record, F_NB_NAME, netbios_name.c_str());
	}

	const char* get_unirec_tmplt() const { return NETBIOS_UNIREC_TEMPLATE; }
#endif

	virtual int fill_ipfix(uint8_t* buffer, int size)
	{
		int length = netbios_name.length();

		if (2 + length > size) {
			return -1;
		}

		buffer[0] = netbios_suffix;
		buffer[1] = length;
		memcpy(buffer + 2, netbios_name.c_str(), length);

		return length + 2;
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_netbios_template[]
			= {IPFIX_NETBIOS_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};
		return ipfix_netbios_template;
	}

	std::string get_text() const
	{
		std::ostringstream out;
		out << "netbiossuffix=" << netbios_suffix << ",name=\"" << netbios_name << "\"";
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing NETBIOS packets.
 */
class NETBIOSPlugin : public ProcessPlugin {
public:
	NETBIOSPlugin(const std::string& params);
	~NETBIOSPlugin();
	void init(const char* params);
	void close();
	OptionsParser* get_parser() const
	{
		return new OptionsParser("netbios", "Parse netbios traffic");
	}
	std::string get_name() const { return "netbios"; }
	RecordExt* get_ext() const { return new RecordExtNETBIOS(); }
	ProcessPlugin* copy();

	int post_create(Flow& rec, const Packet& pkt);
	int post_update(Flow& rec, const Packet& pkt);
	void finish(bool print_stats);

private:
	int total_netbios_packets;

	int add_netbios_ext(Flow& rec, const Packet& pkt);
	bool parse_nbns(RecordExtNETBIOS* rec, const Packet& pkt);
	int get_query_count(const char* payload, uint16_t payload_length);
	bool store_first_query(const char* payload, RecordExtNETBIOS* rec);
	char compress_nbns_name_char(const char* uncompressed);
	uint8_t get_nbns_suffix(const char* uncompressed);
};

} // namespace ipxp
