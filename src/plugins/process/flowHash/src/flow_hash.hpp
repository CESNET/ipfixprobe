/**
 * @file
 * @brief Plugin for processing flow_hash value.
 * @author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstring>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <sstream>
#include <string>

#include <ipfixprobe/byte-utils.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/processPlugin.hpp>

namespace ipxp {

#define FLOW_HASH_UNIREC_TEMPLATE "FLOW_ID"

UR_FIELDS(uint64 FLOW_ID)

/**
 * \brief Flow record extension header for storing parsed FLOW_HASH data.
 */
struct RecordExtFLOW_HASH : public RecordExt {
	static int REGISTERED_ID;

	// Value in host byte order
	uint64_t flow_hash;

	RecordExtFLOW_HASH()
		: RecordExt(REGISTERED_ID)
	{
		flow_hash = 0;
	}

#ifdef WITH_NEMEA
	void fill_unirec(ur_template_t* tmplt, void* record) override
	{
		ur_set(tmplt, record, F_FLOW_ID, flow_hash);
	}

	const char* get_unirec_tmplt() const { return FLOW_HASH_UNIREC_TEMPLATE; }
#endif

	int fill_ipfix(uint8_t* buffer, int size) override
	{
		constexpr int LEN = sizeof(flow_hash);

		if (size < LEN) {
			return -1;
		}

		// value is converted from host byte-order to network byte-order
		*reinterpret_cast<decltype(flow_hash)*>(buffer) = swap_uint64(flow_hash);

		return LEN;
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_template[] = {IPFIX_FLOW_HASH_TEMPLATE(IPFIX_FIELD_NAMES) NULL};
		return ipfix_template;
	}

	std::string get_text() const
	{
		std::ostringstream out;
		out << std::hex << "flow_id=\"" << flow_hash << '"';

		return out.str();
	}
};

/**
 * \brief Process plugin for parsing FLOW_HASH packets.
 */
class FLOW_HASHPlugin : public ProcessPlugin {
public:
	FLOW_HASHPlugin(const std::string& params);
	~FLOW_HASHPlugin();
	void init(const char* params);
	void close();
	OptionsParser* get_parser() const
	{
		return new OptionsParser("flow_hash", "Export flow hash as flow id");
	}
	std::string get_name() const { return "flow_hash"; }
	RecordExt* get_ext() const { return new RecordExtFLOW_HASH(); }
	ProcessPlugin* copy();

	int post_create(Flow& rec, const Packet& pkt);
};

} // namespace ipxp
