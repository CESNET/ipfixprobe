/**
 * \file ipfix.cpp
 * \brief Export flows in IPFIX format.
 *    The following, modified, code was used https://dior.ics.muni.cz/~velan/flowmon-export-ipfix/
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2012 Masaryk University, Institute of Computer Science
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 * 3. Neither the name of the Masaryk University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <config.h>
#include <endian.h>
#include <errno.h>
#include <memory>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "ipfix.hpp"
#include <ipfixprobe/byte-utils.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/output.hpp>
#include <ipfixprobe/process.hpp>

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
    static PluginRecord rec = PluginRecord("ipfix", []() { return new IPFIXExporter(); });
    register_plugin(&rec);
}

#define GCC_CHECK_PRAGMA ((__GNUC__ == 4 && 6 <= __GNUC_MINOR__) || 4 < __GNUC__)

#define FIELD_EN_INT(EN, ID, LEN, SRC) EN
#define FIELD_ID_INT(EN, ID, LEN, SRC) ID
#define FIELD_LEN_INT(EN, ID, LEN, SRC) LEN
#define FIELD_SOURCE_INT(EN, ID, LEN, SRC) SRC

#define FIELD_EN(A) A(FIELD_EN_INT)
#define FIELD_ID(A) A(FIELD_ID_INT)
#define FIELD_LEN(A) A(FIELD_LEN_INT)
#define FIELD_SOURCE(A) A(FIELD_SOURCE_INT)

#define F(ENUMBER, EID, LENGTH, SOURCE) ENUMBER, EID, LENGTH
#define X(FIELD) {#FIELD, FIELD(F)},

/**
 * Copy value into buffer and swap bytes if needed.
 *
 * \param[out] TARGET pointer to the first byte of the current field in buffer
 * \param[in] SOURCE pointer to source of data
 * \param[in] LENGTH size of data in bytes
 */
#define IPFIX_FILL_FIELD(TARGET, FIELD)                                                            \
    do {                                                                                           \
        if (FIELD_LEN(FIELD) == 1) {                                                               \
            *((uint8_t*) TARGET) = *((uint8_t*) FIELD_SOURCE(FIELD));                              \
        } else if (FIELD_LEN(FIELD) == 2) {                                                        \
            *((uint16_t*) TARGET) = htons(*((uint16_t*) FIELD_SOURCE(FIELD)));                     \
        } else if (                                                                                \
            (FIELD_EN(FIELD) == 0)                                                                 \
            && ((FIELD_ID(FIELD) == FIELD_ID(L3_IPV4_ADDR_SRC))                                    \
                || (FIELD_ID(FIELD) == FIELD_ID(L3_IPV4_ADDR_DST)))) {                             \
            *((uint32_t*) TARGET) = *((uint32_t*) FIELD_SOURCE(FIELD));                            \
        } else if (FIELD_LEN(FIELD) == 4) {                                                        \
            *((uint32_t*) TARGET) = htonl(*((uint32_t*) FIELD_SOURCE(FIELD)));                     \
        } else if (FIELD_LEN(FIELD) == 8) {                                                        \
            *((uint64_t*) TARGET) = swap_uint64(*((uint64_t*) FIELD_SOURCE(FIELD)));               \
        } else {                                                                                   \
            memcpy(TARGET, (void*) FIELD_SOURCE(FIELD), FIELD_LEN(FIELD));                         \
        }                                                                                          \
        TARGET += FIELD_LEN(FIELD);                                                                \
    } while (0)

/*
 * IPFIX template fields.
 *
 * name enterprise-number element-id length
 */
template_file_record_t ipfix_fields[][1] = {IPFIX_ENABLED_TEMPLATES(X) nullptr};

/* Basic IPv4 template. */
const char* basic_tmplt_v4[] = {BASIC_TMPLT_V4(IPFIX_FIELD_NAMES) nullptr};

/* Basic IPv6 template. */
const char* basic_tmplt_v6[] = {BASIC_TMPLT_V6(IPFIX_FIELD_NAMES) nullptr};

IPFIXExporter::IPFIXExporter()
    : extensions(nullptr)
    , extension_cnt(0)
    , templates(nullptr)
    , templatesDataSize(0)
    , basic_ifc_num(-1)
    , verbose(false)
    , sequenceNum(0)
    , exportedPackets(0)
    , fd(-1)
    , addrinfo(nullptr)
    , host("")
    , port(4739)
    , protocol(IPPROTO_TCP)
    , ip(AF_UNSPEC)
    , flags(0)
    , reconnectTimeout(RECONNECT_TIMEOUT)
    , lastReconnect(0)
    , odid(0)
    , templateRefreshTime(TEMPLATE_REFRESH_TIME)
    , templateRefreshPackets(TEMPLATE_REFRESH_PACKETS)
    , dir_bit_field(0)
    , mtu(DEFAULT_MTU)
    , packetDataBuffer(nullptr)
    , tmpltMaxBufferSize(mtu - IPFIX_HEADER_SIZE)
{
}

IPFIXExporter::~IPFIXExporter()
{
    close();
}

void IPFIXExporter::init(const char* params)
{
    IpfixOptParser parser;
    try {
        parser.parse(params);
    } catch (ParserError& e) {
        throw PluginError(e.what());
    }
    verbose = parser.m_verbose;
    if (verbose) {
        fprintf(stderr, "VERBOSE: IPFIX export plugin init start\n");
    }

    host = parser.m_host;
    port = parser.m_port;
    odid = parser.m_id;
    mtu = parser.m_mtu;
    dir_bit_field = parser.m_dir;
    templateRefreshTime = parser.m_template_refresh_time;

    if (parser.m_udp) {
        protocol = IPPROTO_UDP;
    }

    if (mtu <= IPFIX_HEADER_SIZE) {
        throw PluginError(
            "IPFIX message MTU size should be at least " + std::to_string(IPFIX_HEADER_SIZE));
    }
    tmpltMaxBufferSize = mtu - IPFIX_HEADER_SIZE;
    packetDataBuffer = (uint8_t*) malloc(sizeof(uint8_t) * mtu);
    if (!packetDataBuffer) {
        throw PluginError("not enough memory");
    }

    int ret = connect_to_collector();
    if (ret) {
        lastReconnect = time(nullptr);
    }

    if (verbose) {
        fprintf(stderr, "VERBOSE: IPFIX export plugin init end\n");
    }
}

void IPFIXExporter::init(const char* params, Plugins& plugins)
{
    init(params);

    extension_cnt = get_extension_cnt();
    if (extension_cnt > 64) {
        throw PluginError("output plugin operates only with up to 64 running plugins");
    }
    extensions = new RecordExt*[extension_cnt];
    for (int i = 0; i < extension_cnt; i++) {
        extensions[i] = nullptr;
    }
    for (auto& it : plugins) {
        std::string name = it.first;
        ProcessPlugin* plugin = it.second;
        RecordExt* ext = plugin->get_ext();
        if (ext == nullptr) {
            continue;
        }
        if (ext->m_ext_id >= 64) {
            throw PluginError("detected plugin ID >64");
        } else if (ext->m_ext_id >= extension_cnt) {
            throw PluginError("detected plugin ID larger than number of extensions");
        }
        delete ext;
    }
}

void IPFIXExporter::close()
{
    /* Try to flush any remaining data */
    flush();

    /* Close the connection */
    if (fd != -1) {
        ::close(fd);
        freeaddrinfo(addrinfo);
        addrinfo = nullptr;
        fd = -1;
    }

    template_t* tmp = templates;
    while (tmp != nullptr) {
        templates = templates->next;
        free(tmp->buffer);
        free(tmp);
        tmp = templates;
    }
    templates = nullptr;

    if (packetDataBuffer != nullptr) {
        free(packetDataBuffer);
        packetDataBuffer = nullptr;
    }
    if (extensions != nullptr) {
        delete[] extensions;
        extensions = nullptr;
    }
}

uint64_t IPFIXExporter::get_template_id(const Record& flow)
{
    RecordExt* ext = flow.m_exts;
    uint64_t tmpltIdx = 0;
    while (ext != nullptr) {
        tmpltIdx |= ((uint64_t) 1 << ext->m_ext_id);
        ext = ext->m_next;
    }

    return tmpltIdx;
}

template_t* IPFIXExporter::get_template(const Flow& flow)
{
    int ipTmpltIdx = flow.ip_version == IP::v6 ? TMPLT_IDX_V6 : TMPLT_IDX_V4;
    uint64_t tmpltIdx = get_template_id(flow);

    if (tmpltMap[ipTmpltIdx].find(tmpltIdx) == tmpltMap[ipTmpltIdx].end()) {
        std::vector<const char*> all_fields;

        RecordExt* ext = flow.m_exts;
        while (ext != nullptr) {
            if (ext->m_ext_id < 0 || ext->m_ext_id >= extension_cnt) {
                throw PluginError("encountered invalid extension id");
            }
            extensions[ext->m_ext_id] = ext;
            ext = ext->m_next;
        }
        for (int i = 0; i < extension_cnt; i++) {
            if (extensions[i] == nullptr) {
                continue;
            }
            const char** fields = extensions[i]->get_ipfix_tmplt();
            extensions[i] = nullptr;
            if (fields == nullptr) {
                throw PluginError(
                    "missing template fields for extension with ID " + std::to_string(i));
            }
            while (*fields != nullptr) {
                all_fields.push_back(*fields);
                fields++;
            }
        }
        all_fields.push_back(nullptr);

        tmpltMap[TMPLT_IDX_V4][tmpltIdx] = create_template(basic_tmplt_v4, all_fields.data());
        tmpltMap[TMPLT_IDX_V6][tmpltIdx] = create_template(basic_tmplt_v6, all_fields.data());
    }

    return tmpltMap[ipTmpltIdx][tmpltIdx];
}

int IPFIXExporter::fill_extensions(RecordExt* ext, uint8_t* buffer, int size)
{
    int length = 0;
    int extCnt = 0;
    while (ext != nullptr) {
        extensions[ext->m_ext_id] = ext;
        extCnt++;
        ext = ext->m_next;
    }
    // TODO: export multiple extension header of same type
    for (int i = 0; i < extension_cnt; i++) {
        if (extensions[i] == nullptr) {
            continue;
        }
        int length_ext = extensions[i]->fill_ipfix(buffer + length, size - length);
        extensions[i] = nullptr;
        if (length_ext < 0) {
            for (int j = i; j < extension_cnt; j++) {
                extensions[j] = nullptr;
            }
            return -1;
        }
        length += length_ext;
    }
    return length;
}

bool IPFIXExporter::fill_template(const Flow& flow, template_t* tmplt)
{
    RecordExt* ext = flow.m_exts;
    int length = 0;

    if (basic_ifc_num >= 0 && ext == nullptr) {
        length = fill_basic_flow(flow, tmplt);
        if (length < 0) {
            return false;
        }
    } else {
        length = fill_basic_flow(flow, tmplt);
        if (length < 0) {
            return false;
        }

        int ext_written = fill_extensions(
            ext,
            tmplt->buffer + tmplt->bufferSize + length,
            tmpltMaxBufferSize - tmplt->bufferSize - length);
        if (ext_written < 0) {
            return false;
        }
        length += ext_written;
    }

    tmplt->bufferSize += length;
    tmplt->recordCount++;
    return true;
}

int IPFIXExporter::export_flow(const Flow& flow)
{
    m_flows_seen++;
    template_t* tmplt = get_template(flow);
    if (!fill_template(flow, tmplt)) {
        flush();

        if (!fill_template(flow, tmplt)) {
            m_flows_dropped++;
            return 1;
        }
    }
    return 0;
}

/**
 * \brief Initialise buffer for record with Data Set Header
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Set ID               |          Length               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * @param tmpl Template to init
 */
void IPFIXExporter::init_template_buffer(template_t* tmpl)
{
    *((uint16_t*) &tmpl->buffer[0]) = htons(tmpl->id);
    /* Length will be updated later */
    /* *((uint16_t *) &tmpl->buffer[2]) = htons(0); */
    tmpl->bufferSize = 4;
}

/**
 * \brief Fill ipfix template set header to memory specified by pointer
 *
 * @param ptr Pointer to memory to fill. Should be at least 4 bytes long
 * @param size Size of the template set including set header
 * @return size of the template set header
 */
int IPFIXExporter::fill_template_set_header(uint8_t* ptr, uint16_t size)
{
    ipfix_template_set_header_t* header = (ipfix_template_set_header_t*) ptr;

    header->id = htons(TEMPLATE_SET_ID);
    header->length = htons(size);

    return IPFIX_SET_HEADER_SIZE;
}

/**
 * \brief Check whether timeouts for template expired and set exported flag accordingly
 *
 * @param tmpl Template to check
 */
void IPFIXExporter::check_template_lifetime(template_t* tmpl)
{
    if (templateRefreshTime != 0
        && (time_t) (templateRefreshTime + tmpl->exportTime) <= time(nullptr)) {
        if (verbose) {
            fprintf(
                stderr,
                "VERBOSE: Template %i refresh time expired (%is)\n",
                tmpl->id,
                templateRefreshTime);
        }
        tmpl->exported = 0;
    }

    if (templateRefreshPackets != 0
        && templateRefreshPackets + tmpl->exportPacket <= exportedPackets) {
        if (verbose) {
            fprintf(
                stderr,
                "VERBOSE: Template %i refresh packets expired (%i packets)\n",
                tmpl->id,
                templateRefreshPackets);
        }
        tmpl->exported = 0;
    }
}

/**
 * \brief Fill ipfix header to memory specified by pointer
 *
 * @param ptr Pointer to memory to fill. Should be at least 16 bytes long
 * @param size Size of the IPFIX packet not including the header.
 * @return Returns size of the header
 */
int IPFIXExporter::fill_ipfix_header(uint8_t* ptr, uint16_t size)
{
    ipfix_header_t* header = (ipfix_header_t*) ptr;

    header->version = htons(IPFIX_VERISON);
    header->length = htons(size);
    header->exportTime = htonl(time(nullptr));
    header->sequenceNumber = htonl(sequenceNum);
    header->observationDomainId = htonl(odid);

    return IPFIX_HEADER_SIZE;
}

/**
 * \brief Get template record from template file by name
 *
 * @param name Name of the record to find
 * @return Template File Record with matching name or nullptr when non exists
 */
template_file_record_t* IPFIXExporter::get_template_record_by_name(const char* name)
{
    template_file_record_t* tmpFileRecord = *ipfix_fields;

    if (name == nullptr) {
        if (verbose) {
            fprintf(stderr, "VERBOSE: Cannot get template for nullptr name\n");
        }
        return nullptr;
    }

    while (tmpFileRecord && tmpFileRecord->name) {
        if (strcmp(name, tmpFileRecord->name) == 0) {
            return tmpFileRecord;
        }
        tmpFileRecord++;
    }

    return nullptr;
}

/**
 * \brief Set all templates as expired
 */
void IPFIXExporter::expire_templates()
{
    template_t* tmp;
    for (tmp = templates; tmp != nullptr; tmp = tmp->next) {
        tmp->exported = 0;
        if (protocol == IPPROTO_UDP) {
            tmp->exportTime = time(nullptr);
            tmp->exportPacket = exportedPackets;
        }
    }
}

/**
 * \brief Create new template based on given record
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      Template ID (> 255)      |         Field Count           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * @param tmplt Template fields string
 * @param ext Template extension fields string
 * @return Created template on success, nullptr otherwise
 */
template_t* IPFIXExporter::create_template(const char** tmplt, const char** ext)
{
    uint16_t maxID = FIRST_TEMPLATE_ID;
    uint16_t len;
    template_t* tmpTemplate = templates;
    template_t* newTemplate;
    const char** tmp = tmplt;

    /* Create new template structure */
    newTemplate = (template_t*) malloc(sizeof(template_t));
    if (!newTemplate) {
        fprintf(stderr, "Error: Not enough memory for IPFIX template.\n");
        return nullptr;
    }

    newTemplate->fieldCount = 0;
    newTemplate->recordCount = 0;
    newTemplate->buffer = (uint8_t*) malloc(sizeof(uint8_t) * tmpltMaxBufferSize);
    if (!newTemplate->buffer) {
        free(newTemplate);
        fprintf(stderr, "Error: Not enough memory for IPFIX template buffer.\n");
        return nullptr;
    }

    /* Set template ID to maximum + 1 */
    while (tmpTemplate != nullptr) {
        if (tmpTemplate->id >= maxID)
            maxID = tmpTemplate->id + 1;
        tmpTemplate = tmpTemplate->next;
    }
    newTemplate->id = maxID;
    ((uint16_t*) newTemplate->templateRecord)[0] = htons(newTemplate->id);

    if (verbose) {
        fprintf(stderr, "VERBOSE: Creating new template id %u\n", newTemplate->id);
    }

    /* Template header size */
    newTemplate->templateSize = 4;

    while (1) {
        while (tmp && *tmp) {
            assert(newTemplate->templateSize + 8u < sizeof(newTemplate->templateRecord));
            /* Find appropriate template file record */
            template_file_record_t* tmpFileRecord = get_template_record_by_name(*tmp);
            if (tmpFileRecord != nullptr) {
                if (verbose) {
                    fprintf(
                        stderr,
                        "VERBOSE: Adding template field name=%s EN=%u ID=%u len=%d\n",
                        tmpFileRecord->name,
                        tmpFileRecord->enterpriseNumber,
                        tmpFileRecord->elementID,
                        tmpFileRecord->length);
                }

                /* Set information element ID */
                uint16_t eID = tmpFileRecord->elementID;
                if (tmpFileRecord->enterpriseNumber != 0) {
                    eID |= 0x8000;
                }
                *((uint16_t*) &newTemplate->templateRecord[newTemplate->templateSize]) = htons(eID);

                /* Set element length */
                if (tmpFileRecord->length == 0) {
                    fprintf(stderr, "Error: Template field cannot be zero length.\n");
                    free(newTemplate);
                    return nullptr;
                } else {
                    len = tmpFileRecord->length;
                }
                *((uint16_t*) &newTemplate->templateRecord[newTemplate->templateSize + 2])
                    = htons(len);

                /* Update template size */
                newTemplate->templateSize += 4;

                /* Add enterprise number if required */
                if (tmpFileRecord->enterpriseNumber != 0) {
                    *((uint32_t*) &newTemplate->templateRecord[newTemplate->templateSize])
                        = htonl(tmpFileRecord->enterpriseNumber);
                    newTemplate->templateSize += 4;
                }

                /* Increase field count */
                newTemplate->fieldCount++;
            } else {
                fprintf(stderr, "Error: Cannot find field specification for name %s\n", *tmp);
                free(newTemplate);
                return nullptr;
            }

            tmp++;
        }

        if (ext == nullptr) {
            break;
        }
        tmp = ext;
        ext = nullptr;
    }

    /* Set field count */
    ((uint16_t*) newTemplate->templateRecord)[1] = htons(newTemplate->fieldCount);

    /* Initialize buffer for records */
    init_template_buffer(newTemplate);

    /* Update total template size */
    templatesDataSize += newTemplate->bufferSize;

    /* The template was not exported yet */
    newTemplate->exported = 0;
    newTemplate->exportTime = time(nullptr);
    newTemplate->exportPacket = exportedPackets;

    /* Add the new template to the list */
    newTemplate->next = templates;
    templates = newTemplate;

    return newTemplate;
}

/**
 * \brief Creates template packet
 *
 * Sets used templates as exported!
 *
 * @param packet Pointer to packet to fill
 * @return IPFIX packet with templates to export or nullptr on failure
 */
uint16_t IPFIXExporter::create_template_packet(ipfix_packet_t* packet)
{
    template_t* tmp = templates;
    uint16_t totalSize = 0;
    uint8_t* ptr;

    /* Get total size */
    while (tmp != nullptr) {
        /* Check UDP template lifetime */
        if (protocol == IPPROTO_UDP) {
            check_template_lifetime(tmp);
        }
        if (tmp->exported == 0) {
            totalSize += tmp->templateSize;
        }
        tmp = tmp->next;
    }

    /* Check that there are templates to export */
    if (totalSize == 0) {
        return 0;
    }

    totalSize += IPFIX_HEADER_SIZE + IPFIX_SET_HEADER_SIZE;

    /* Allocate memory for the packet */
    packet->data = (uint8_t*) malloc(sizeof(uint8_t) * (totalSize));
    if (!packet->data) {
        return 0;
    }
    ptr = packet->data;

    /* Create ipfix message header */
    ptr += fill_ipfix_header(ptr, totalSize);
    /* Create template set header */
    ptr += fill_template_set_header(ptr, totalSize - IPFIX_HEADER_SIZE);

    /* Copy the templates to the packet */
    tmp = templates;
    while (tmp != nullptr) {
        if (tmp->exported == 0) {
            memcpy(ptr, tmp->templateRecord, tmp->templateSize);
            ptr += tmp->templateSize;
            /* Set the templates as exported, store time and serial number */
            tmp->exported = 1;
            tmp->exportTime = time(nullptr);
            tmp->exportPacket = exportedPackets;
        }
        tmp = tmp->next;
    }

    packet->length = totalSize;
    packet->flows = 0;

    return totalSize;
}

/**
 * \brief Creates data packet from template buffers
 *
 * Removes the data from the template buffers
 *
 * @param packet Pointer to packet to fill
 * @return length of the IPFIX data packet on success, 0 otherwise
 */
uint16_t IPFIXExporter::create_data_packet(ipfix_packet_t* packet)
{
    template_t* tmp = templates;
    uint16_t totalSize = IPFIX_HEADER_SIZE; /* Include IPFIX header to total size */
    uint32_t deltaSequenceNum = 0; /* Number of exported records in this packet */
    uint8_t* ptr;

    /* Start adding data after the header */
    ptr = packet->data + totalSize;

    /* Copy the data sets to the packet */
    templatesDataSize = 0; /* Erase total data size */
    while (tmp != nullptr) {
        /* Add only templates with data that fits to one packet */
        if (tmp->recordCount > 0 && totalSize + tmp->bufferSize <= mtu) {
            memcpy(ptr, tmp->buffer, tmp->bufferSize);
            /* Set SET length */
            ((ipfix_template_set_header_t*) ptr)->length = htons(tmp->bufferSize);
            if (verbose) {
                fprintf(
                    stderr,
                    "VERBOSE: Adding template %i of length %i to data packet\n",
                    tmp->id,
                    tmp->bufferSize);
            }
            ptr += tmp->bufferSize;
            /* Count size of the data copied to buffer */
            totalSize += tmp->bufferSize;
            /* Delete data from buffer */
            tmp->bufferSize = IPFIX_SET_HEADER_SIZE;

            /* Store number of exported records  */
            deltaSequenceNum += tmp->recordCount;
            tmp->recordCount = 0;
        }
        /* Update total data size, include empty template buffers (only set headers) */
        templatesDataSize += tmp->bufferSize;
        tmp = tmp->next;
    }

    /* Check that there are packets to export */
    if (totalSize == IPFIX_HEADER_SIZE) {
        return 0;
    }

    /* Create ipfix message header at the beginning */
    fill_ipfix_header(packet->data, totalSize);

    /* Fill number of flows and size of the packet */
    packet->flows = deltaSequenceNum;
    packet->length = totalSize;

    return totalSize;
}

/**
 * \brief Send all new templates to collector
 */
void IPFIXExporter::send_templates()
{
    ipfix_packet_t pkt;

    /* Send all new templates */
    if (create_template_packet(&pkt)) {
        /* Send template packet */
        /* After error, the plugin sends all templates after reconnection,
         * so we need not concern about it here */
        send_packet(&pkt);

        free(pkt.data);
    }
}

/**
 * \brief Send data in all buffers to collector
 */
void IPFIXExporter::send_data()
{
    ipfix_packet_t pkt;
    pkt.data = packetDataBuffer;

    /* Send all new templates */
    while (create_data_packet(&pkt)) {
        int ret = send_packet(&pkt);
        if (ret == 1) {
            /* Collector reconnected, resend the packet */
            ret = send_packet(&pkt);
        }
        if (ret != 0) {
            m_flows_dropped += pkt.flows;
        }
    }
}

/**
 * \brief Export stored flows.
 */
void IPFIXExporter::flush()
{
    /* Send all new templates */
    send_templates();

    /* Send the data packet */
    send_data();
}

/**
 * \brief Sends packet using UDP or TCP as defined in plugin configuration
 *
 * When the collector disconnects, tries to reconnect and resend the data
 *
 * \param packet Packet to send
 * \return 0 on success, -1 on socket error, 1 when data needs to be resent (after reconnect)
 */
int IPFIXExporter::send_packet(ipfix_packet_t* packet)
{
    int ret; /* Return value of sendto */
    int sent = 0; /* Sent data size */

    /* Check that connection is OK or drop packet */
    if (reconnect()) {
        return -1;
    }

    /* sendto() does not guarantee that everything will be send in one piece */
    while (sent < packet->length) {
        /* Send data to collector (TCP and SCTP ignores last two arguments) */
        ret = sendto(
            fd,
            (void*) (packet->data + sent),
            packet->length - sent,
            0,
            addrinfo->ai_addr,
            addrinfo->ai_addrlen);

        /* Check that the data were sent correctly */
        if (ret == -1) {
            switch (errno) {
            case 0:
                break; /* OK */
            case ECONNRESET:
            case EINTR:
            case ENOTCONN:
            case ENOTSOCK:
            case EPIPE:
            case EHOSTUNREACH:
            case ENETDOWN:
            case ENETUNREACH:
            case ENOBUFS:
            case ENOMEM:

                /* The connection is broken */
                if (verbose) {
                    fprintf(stderr, "VERBOSE: Collector closed connection\n");
                }

                /* free resources */
                ::close(fd);
                fd = -1;
                freeaddrinfo(addrinfo);
                addrinfo = nullptr;

                /* Set last connection try time so that we would reconnect immediatelly */
                lastReconnect = 1;

                /* Reset the sequences number since it is unique per connection */
                sequenceNum = 0;
                ((ipfix_header_t*) packet->data)->sequenceNumber
                    = 0; /* no need to change byteorder of 0 */

                /* Say that we should try to connect and send data again */
                return 1;
            default:
                /* Unknown error */
                if (verbose) {
                    perror("VERBOSE: Cannot send data to collector");
                }
                return -1;
            }
        }

        /* No error from sendto(), add sent data count to total */
        sent += ret;
    }

    /* Update sequence number for next packet */
    sequenceNum += packet->flows;

    /* Increase packet counter */
    exportedPackets++;

    if (verbose) {
        fprintf(
            stderr,
            "VERBOSE: Packet (%" PRIu64 ") sent to %s on port %" PRIu16
            ". Next sequence number is %i\n",
            exportedPackets,
            host.c_str(),
            port,
            sequenceNum);
    }

    return 0;
}

/**
 * \brief Create connection to collector
 *
 * The created socket is stored in conf->socket, addrinfo in conf->addrinfo
 * Addrinfo is freed up and socket is disconnected on error
 *
 * @return 0 on success, 1 on socket error or 2 when target is not listening
 */
int IPFIXExporter::connect_to_collector()
{
    struct addrinfo hints, *tmp;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = ip;
    hints.ai_socktype = protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = protocol;
    hints.ai_flags = AI_ADDRCONFIG | flags;

    err = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &addrinfo);
    if (err) {
        const char* err_msg = nullptr;
        if (err == EAI_SYSTEM) {
            err_msg = strerror(errno);
        } else {
            err_msg = gai_strerror(err);
        }
        if (verbose) {
            fprintf(stderr, "Cannot get server info: %s\n", err_msg);
        }
        return 1;
    }

    /* Try addrinfo strucutres one by one */
    for (tmp = addrinfo; tmp != nullptr; tmp = tmp->ai_next) {
        if (tmp->ai_family != AF_INET && tmp->ai_family != AF_INET6) {
            continue;
        }

        /* Print information about target address */
        char buff[INET6_ADDRSTRLEN];
        inet_ntop(
            tmp->ai_family,
            (tmp->ai_family == AF_INET) ? (void*) &((struct sockaddr_in*) tmp->ai_addr)->sin_addr
                                        : (void*) &((struct sockaddr_in6*) tmp->ai_addr)->sin6_addr,
            (char*) &buff,
            sizeof(buff));

        if (verbose) {
            fprintf(stderr, "VERBOSE: Connecting to IP %s\n", buff);
            fprintf(
                stderr,
                "VERBOSE: Socket configuration: AI Family: %i, AI Socktype: %i, AI Protocol: %i\n",
                tmp->ai_family,
                tmp->ai_socktype,
                tmp->ai_protocol);
        }

        /* create socket */
        fd = socket(tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
        if (fd == -1) {
            if (verbose) {
                perror("VERBOSE: Cannot create new socket");
            }
            continue;
        }

        /* connect to server with TCP and SCTP */
        if (protocol != IPPROTO_UDP && connect(fd, tmp->ai_addr, tmp->ai_addrlen) == -1) {
            if (verbose) {
                perror("VERBOSE: Cannot connect to collector");
            }
            ::close(fd);
            fd = -1;
            continue;
        }

        /* Connected, meaningless for UDP */
        if (protocol != IPPROTO_UDP) {
            if (verbose) {
                fprintf(stderr, "VERBOSE: Successfully connected to collector\n");
            }
        }
        break;
    }

    /* Return error when all addrinfo structures were tried*/
    if (tmp == nullptr) {
        /* Free allocated resources */
        freeaddrinfo(addrinfo);
        addrinfo = nullptr;
        return 2;
    }

    return 0;
}

/**
 * \brief Checks that connection is OK or tries to reconnect
 *
 * @return 0 when connection is OK or reestablished, 1 when not
 */
int IPFIXExporter::reconnect()
{
    /* Check for broken connection */
    if (lastReconnect != 0) {
        /* Check whether we need to attempt reconnection */
        if ((time_t) (lastReconnect + reconnectTimeout) <= time(nullptr)) {
            /* Try to reconnect */
            if (connect_to_collector() == 0) {
                lastReconnect = 0;
                /* Resend all templates */
                expire_templates();
                send_templates();
            } else {
                /* Set new reconnect time and drop packet */
                lastReconnect = time(nullptr);
                return 1;
            }
        } else {
            /* Timeout not reached, drop packet */
            return 1;
        }
    }

    return 0;
}

#define GEN_FIELDS_SUMLEN_INT(FIELD) FIELD_LEN(FIELD) +
#define GEN_FILLFIELDS_INT(TMPLT) IPFIX_FILL_FIELD(p, TMPLT);
#define GEN_FILLFIELDS_MAXLEN(TMPLT) IPFIX_FILL_FIELD(p, TMPLT);

#define GENERATE_FILL_FIELDS_V4()                                                                  \
    do {                                                                                           \
        BASIC_TMPLT_V4(GEN_FILLFIELDS_INT)                                                         \
    } while (0)

#define GENERATE_FILL_FIELDS_V6()                                                                  \
    do {                                                                                           \
        BASIC_TMPLT_V6(GEN_FILLFIELDS_INT)                                                         \
    } while (0)

#define GENERATE_FIELDS_SUMLEN(TMPL) TMPL(GEN_FIELDS_SUMLEN_INT) 0

/**
 * \brief Fill template buffer with flow.
 * @param flow Flow
 * @param tmplt Template containing buffer
 * @return Number of written bytes or -1 if buffer is not big enough
 */
int IPFIXExporter::fill_basic_flow(const Flow& flow, template_t* tmplt)
{
    uint8_t *buffer, *p;
    int length;
    uint64_t temp;

    buffer = tmplt->buffer + tmplt->bufferSize;
    p = buffer;
    if (flow.ip_version == IP::v4) {
        if (tmplt->bufferSize + GENERATE_FIELDS_SUMLEN(BASIC_TMPLT_V4) > tmpltMaxBufferSize) {
            return -1;
        }

        /* Temporary disable warnings about breaking string-aliasing, since it is produced by
         * if-branches that are never going to be used - generated by C-preprocessor.
         */
#if GCC_CHECK_PRAGMA
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif
        /* Generate code for copying values of IPv4 template into IPFIX message. */
        GENERATE_FILL_FIELDS_V4();
#if GCC_CHECK_PRAGMA
#pragma GCC diagnostic pop
#endif

    } else {
        if (tmplt->bufferSize + GENERATE_FIELDS_SUMLEN(BASIC_TMPLT_V6) > tmpltMaxBufferSize) {
            return -1;
        }

        /* Temporary disable warnings about breaking string-aliasing, since it is produced by
         * if-branches that are never going to be used - generated by C-preprocessor.
         */
#if GCC_CHECK_PRAGMA
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif
        /* Generate code for copying values of IPv6 template into IPFIX message. */
        GENERATE_FILL_FIELDS_V6();
#if GCC_CHECK_PRAGMA
#pragma GCC diagnostic pop
#endif
    }

    length = p - buffer;

    return length;
}

} // namespace ipxp
