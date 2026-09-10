/**
 * @file
 * @brief Plugin for parsing packet info arriving via the "sock" input plugin.
 * @author Lokesh Dhoundiyal <lokesh.dhoundial@alliedtelesis.co.nz>
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

#include <cstdint>
#include <sstream>
#include <string>

//#include <ipfixprobe/byte-utils.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/processPlugin.hpp>

namespace ipxp {

#define SOCKPKTINFO_UNIREC_TEMPLATE "ING_PHY_INTERFACE,DROPS"

UR_FIELDS(
	uint32 ING_PHY_INTERFACE,
	uint64 DROPS)

/**
 * \brief Flow record extension header for storing parsed SOCKPKTINFO data.
 */
struct RecordExtSOCKPKTINFO : public RecordExt {
	uint32_t ing_phy_interface;
	uint32_t drop_packets;

	RecordExtSOCKPKTINFO(int pluginID)
		: RecordExt(pluginID)
		, ing_phy_interface(0)
		, drop_packets(0)
	{
	}

	#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_ING_PHY_INTERFACE, ing_phy_interface);
		ur_set(tmplt, record, F_DROPS, drop_packets);
	}

	const char* get_unirec_tmplt() const
	{
		return SOCKPKTINFO_UNIREC_TEMPLATE;
	}
	#endif

	int fill_ipfix(uint8_t* buffer, int size) override
	{
		const int LEN = sizeof(ing_phy_interface) + sizeof(drop_packets);
		if (size < LEN) {
			 return -1;
		}
		*(uint32_t*)buffer = ntohl(ing_phy_interface);
		*(uint32_t*)(buffer + 4) = ntohl(drop_packets);

		return LEN;
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_template[] = {
			IPFIX_SOCKPKTINFO_TEMPLATE(IPFIX_FIELD_NAMES)
				NULL
		};
		return ipfix_template;
	}

	std::string get_text() const
	{
		std::ostringstream out;
		out << "ing_phy_interface=\"" << ing_phy_interface << '"' << ",drop_packets=\"" << drop_packets << '"';
		return out.str();
	}
};

/**
 * \brief Process plugin for parsing SOCKPKTINFO packets.
 */
class SOCKPKTINFOPlugin : public ProcessPlugin {
	public:
	SOCKPKTINFOPlugin(const std::string& params, int pluginID);
	OptionsParser* get_parser() const
	{
		return new OptionsParser(
			"sockpktinfo",
			"Parse SOCKPKTINFO traffic");
	}
	std::string get_name() const
	{
		return "sockpktinfo";
	}
	RecordExt* get_ext() const
	{
		return new RecordExtSOCKPKTINFO(m_pluginID);
	}
	ProcessPlugin* copy();

	int post_create(Flow& rec, const Packet& pkt);
};

} // namespace ipxp

