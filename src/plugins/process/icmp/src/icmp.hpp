/**
 * @file
 * @brief Plugin for parsing icmp traffic.
 * @author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
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

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/processPlugin.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {

#define ICMP_UNIREC_TEMPLATE "L4_ICMP_TYPE_CODE"

UR_FIELDS(uint16 L4_ICMP_TYPE_CODE)

/**
 * \brief Flow record extension header for storing parsed ICMP data.
 */
struct RecordExtICMP : public RecordExt {
	static int REGISTERED_ID;

	uint16_t type_code;

	RecordExtICMP()
		: RecordExt(REGISTERED_ID)
	{
		type_code = 0;
	}

#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_L4_ICMP_TYPE_CODE, ntohs(type_code));
	}

	const char* get_unirec_tmplt() const { return ICMP_UNIREC_TEMPLATE; }
#endif

	virtual int fill_ipfix(uint8_t* buffer, int size)
	{
		const int LEN = 2;

		if (size < LEN) {
			return -1;
		}

		*reinterpret_cast<uint16_t*>(buffer) = type_code;

		return LEN;
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_template[] = {IPFIX_ICMP_TEMPLATE(IPFIX_FIELD_NAMES) NULL};
		return ipfix_template;
	}

	std::string get_text() const
	{
		// type is on the first byte, code is on the second byte
		auto* type_code = reinterpret_cast<const uint8_t*>(&this->type_code);

		std::ostringstream out;
		out << "type=\"" << static_cast<int>(type_code[0]) << '"' << ",code=\""
			<< static_cast<int>(type_code[1]) << '"';

		return out.str();
	}
};

/**
 * \brief Process plugin for parsing ICMP packets.
 */
class ICMPPlugin : public ProcessPlugin {
public:
	ICMPPlugin(const std::string& params);

	OptionsParser* get_parser() const { return new OptionsParser("icmp", "Parse ICMP traffic"); }
	std::string get_name() const { return "icmp"; }
	RecordExt* get_ext() const { return new RecordExtICMP(); }
	ProcessPlugin* copy();

	int post_create(Flow& rec, const Packet& pkt);
};

} // namespace ipxp
