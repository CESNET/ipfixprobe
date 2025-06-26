/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
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

#include <cstdint>
#include <sstream>
#include <string>

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/processPlugin.hpp>

namespace ipxp {

#define VLAN_UNIREC_TEMPLATE "VLAN_ID"

UR_FIELDS(uint16 VLAN_ID)

/**
 * \brief Flow record extension header for storing parsed VLAN data.
 */
struct RecordExtVLAN : public RecordExt {
	// vlan id is in the host byte order
	uint16_t vlan_id;

	RecordExtVLAN(int pluginID)
		: RecordExt(pluginID)
		, vlan_id(0)
	{
	}

#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_VLAN_ID, vlan_id);
	}

	const char* get_unirec_tmplt() const { return VLAN_UNIREC_TEMPLATE; }
#endif

	virtual int fill_ipfix(uint8_t* buffer, int size)
	{
		const int LEN = sizeof(vlan_id);

		if (size < LEN) {
			return -1;
		}

		*reinterpret_cast<uint16_t*>(buffer) = htons(vlan_id);
		return LEN;
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_template[] = {IPFIX_VLAN_TEMPLATE(IPFIX_FIELD_NAMES) NULL};
		return ipfix_template;
	}

	std::string get_text() const
	{
		std::ostringstream out;
		out << "vlan_id=\"" << vlan_id << '"';
		return out.str();
	}
};

/**
 * \brief Process plugin for parsing VLAN packets.
 */
class VLANPlugin : public ProcessPlugin {
public:
	VLANPlugin(const std::string& params, int pluginID);
	OptionsParser* get_parser() const { return new OptionsParser("vlan", "Parse VLAN traffic"); }
	std::string get_name() const { return "vlan"; }
	RecordExt* get_ext() const { return new RecordExtVLAN(m_pluginID); }
	ProcessPlugin* copy();

	ProcessPlugin::FlowAction post_create(Flow& rec, const Packet& pkt);
};

} // namespace ipxp
