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

#define QINQ_UNIREC_TEMPLATE "DOT1Q_VLAN_ID,DOT1Q_CUSTOMER_VLAN_ID"

UR_FIELDS(
	uint16 VLAN_ID;
	uint16 VLAN_ID2;
)


/**
 * \brief Flow record extension header for storing parsed QinQ data.
 */
struct RecordExtQinQ : public RecordExt {
	// vlan id is in the host byte order
	uint16_t vlan_id;
	uint16_t vlan_id2;
	RecordExtQinQ(int pluginID)
		: RecordExt(pluginID)
		, vlan_id(0)
		, vlan_id2(0)
	{
	}

#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_VLAN_ID, vlan_id);
		ur_set(tmplt, record, F_VLAN_ID2, vlan_id2);
	}

	const char* get_unirec_tmplt() const { return QINQ_UNIREC_TEMPLATE; }
#endif

	virtual int fill_ipfix(uint8_t* buffer, int size)
	{
		const int LEN = sizeof(vlan_id);		
		const int LEN2 = sizeof(vlan_id2);
		if( size < (LEN + LEN2) ) {
			return LEN;
		}
		*reinterpret_cast<uint16_t*>(buffer) = htons(vlan_id);
		*reinterpret_cast<uint16_t*>(buffer + LEN) = htons(vlan_id2);
		return (LEN + LEN2);
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_qinq_template[] = {IPFIX_QINQ_TEMPLATE(IPFIX_FIELD_NAMES) NULL};
	    return ipfix_qinq_template;		
	}

	std::string get_text() const
	{
		std::ostringstream out;
		out << "DOT1Q_VLAN_ID=\"" << vlan_id << "\", DOT1Q_CUSTOMER_VLAN_ID=\"" << vlan_id2 << "\"";
		return out.str();
	}
};

/**
 * \brief Process plugin for parsing VLAN packets.
 */
class QinQPlugin : public ProcessPlugin {
public:
	QinQPlugin(const std::string& params, int pluginID);
	OptionsParser* get_parser() const { return new OptionsParser("qinq", "Parse QinQ traffic"); }
	std::string get_name() const { return "qinq"; }
	RecordExt* get_ext() const { return new RecordExtQinQ(m_pluginID); }
	ProcessPlugin* copy();

	int post_create(Flow& rec, const Packet& pkt);
};

} // namespace ipxp
