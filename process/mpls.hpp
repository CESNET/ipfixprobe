/**
 * \file mpls.hpp
 * \brief Plugin for parsing mpls traffic.
 * \author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
 * \date 2023
 */
/*
 * Copyright (C) 2023 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *
 *
 */

#ifndef IPXP_PROCESS_MPLS_HPP
#define IPXP_PROCESS_MPLS_HPP

#include <cstring>
#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace ipxp {

#define MPLS_LABEL_SECTION_LENGTH 3

#define MPLS_UNIREC_TEMPLATE "MPLS_TOP_LABEL_STACK_SECTION"

UR_FIELDS(bytes MPLS_TOP_LABEL_STACK_SECTION)

/**
 * \brief Flow record extension header for storing parsed MPLS data.
 */
struct RecordExtMPLS : public RecordExt {
    static int REGISTERED_ID;

    // Contents are (from MSb to LSb):
    //   20-bit - Label,
    //   3-bit  - Traffic class / EXP,
    //   1-bit  - Bottom of stack (true if last),
    //   8-bit  - TTL (Time To Live)
    uint32_t mpls;

    RecordExtMPLS()
        : RecordExt(REGISTERED_ID)
        , mpls(0)
    {
    }

#ifdef WITH_NEMEA
    void fill_unirec(ur_template_t* tmplt, void* record) override
    {
        auto v = htonl(mpls);
        auto arr = reinterpret_cast<uint8_t*>(&v);
        ur_set_var(tmplt, record, F_MPLS_TOP_LABEL_STACK_SECTION, arr, MPLS_LABEL_SECTION_LENGTH);
    }

    const char* get_unirec_tmplt() const { return MPLS_UNIREC_TEMPLATE; }
#endif

    int fill_ipfix(uint8_t* buffer, int size) override
    {
        if (size < MPLS_LABEL_SECTION_LENGTH + 1) {
            return -1;
        }

        buffer[0] = MPLS_LABEL_SECTION_LENGTH;
        auto v = htonl(mpls);
        auto arr = reinterpret_cast<uint8_t*>(&v);
        memcpy(buffer + 2, arr, MPLS_LABEL_SECTION_LENGTH);

        return MPLS_LABEL_SECTION_LENGTH + 1;
    }

    const char** get_ipfix_tmplt() const
    {
        static const char* ipfix_template[] = {IPFIX_MPLS_TEMPLATE(IPFIX_FIELD_NAMES) NULL};
        return ipfix_template;
    }

    std::string get_text() const
    {
        std::ostringstream out;
        out << "mpls_label_1=\"" << (mpls >> 8) << '"';
        return out.str();
    }
};

/**
 * \brief Process plugin for parsing MPLS packets.
 */
class MPLSPlugin : public ProcessPlugin {
public:
    OptionsParser* get_parser() const { return new OptionsParser("mpls", "Parse MPLS traffic"); }
    std::string get_name() const { return "mpls"; }
    RecordExt* get_ext() const { return new RecordExtMPLS(); }
    ProcessPlugin* copy();

    int post_create(Flow& rec, const Packet& pkt);
};

} // namespace ipxp
#endif /* IPXP_PROCESS_MPLS_HPP */
