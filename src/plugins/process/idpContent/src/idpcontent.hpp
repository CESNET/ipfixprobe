/**
 * @file
 * @brief Plugin for parsing idpcontent traffic.
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/processPlugin.hpp>

namespace ipxp {

#define IDPCONTENT_SIZE 100
#define EXPORTED_PACKETS 2
#define IDP_CONTENT_INDEX 0
#define IDP_CONTENT_REV_INDEX 1

#define IDPCONTENT_UNIREC_TEMPLATE "IDP_CONTENT,IDP_CONTENT_REV"

UR_FIELDS(bytes IDP_CONTENT, bytes IDP_CONTENT_REV)

/**
 * \brief Flow record extension header for storing parsed IDPCONTENT packets.
 */

struct idpcontentArray {
	idpcontentArray()
		: size(0) {};
	uint8_t size;
	uint8_t data[IDPCONTENT_SIZE];
};

struct RecordExtIDPCONTENT : public RecordExt {
	static int REGISTERED_ID;

	uint8_t pkt_export_flg[EXPORTED_PACKETS];
	idpcontentArray idps[EXPORTED_PACKETS];

	RecordExtIDPCONTENT()
		: RecordExt(REGISTERED_ID)
	{
	}

#ifdef WITH_NEMEA
	virtual void fill_unirec(ur_template_t* tmplt, void* record)
	{
		ur_set_var(
			tmplt,
			record,
			F_IDP_CONTENT,
			idps[IDP_CONTENT_INDEX].data,
			idps[IDP_CONTENT_INDEX].size);
		ur_set_var(
			tmplt,
			record,
			F_IDP_CONTENT_REV,
			idps[IDP_CONTENT_REV_INDEX].data,
			idps[IDP_CONTENT_REV_INDEX].size);
	}

	const char* get_unirec_tmplt() const { return IDPCONTENT_UNIREC_TEMPLATE; }
#endif

	virtual int fill_ipfix(uint8_t* buffer, int size)
	{
		uint32_t pos = 0;

		if (idps[IDP_CONTENT_INDEX].size + idps[IDP_CONTENT_REV_INDEX].size + 2 > size) {
			return -1;
		}
		for (int i = 0; i < EXPORTED_PACKETS; i++) {
			buffer[pos++] = idps[i].size;
			memcpy(buffer + pos, idps[i].data, idps[i].size);
			pos += idps[i].size;
		}

		return pos;
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_tmplt[] = {IPFIX_IDPCONTENT_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfix_tmplt;
	}

	std::string get_text() const
	{
		std::ostringstream out;
		out << "idpsrc=";
		for (size_t i = 0; i < idps[IDP_CONTENT_INDEX].size; i++) {
			out << std::hex << std::setw(2) << std::setfill('0') << idps[IDP_CONTENT_INDEX].data[i];
		}
		out << ",idpdst=";
		for (size_t i = 0; i < idps[IDP_CONTENT_REV_INDEX].size; i++) {
			out << std::hex << std::setw(2) << std::setfill('0')
				<< idps[IDP_CONTENT_REV_INDEX].data[i];
		}
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing IDPCONTENT packets.
 */
class IDPCONTENTPlugin : public ProcessPlugin {
public:
	IDPCONTENTPlugin(const std::string& params);
	~IDPCONTENTPlugin();
	void init(const char* params);
	void close();
	OptionsParser* get_parser() const
	{
		return new OptionsParser("idpcontent", "Parse first bytes of flow payload");
	}
	std::string get_name() const { return "idpcontent"; }
	RecordExt* get_ext() const { return new RecordExtIDPCONTENT(); }
	ProcessPlugin* copy();

	int post_create(Flow& rec, const Packet& pkt);
	int post_update(Flow& rec, const Packet& pkt);
	void update_record(RecordExtIDPCONTENT* pstats_data, const Packet& pkt);
};

} // namespace ipxp
