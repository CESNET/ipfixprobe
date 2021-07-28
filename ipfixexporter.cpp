/**
 * \file ipfixexporter.cpp
 * \brief Export flows in IPFIX format.
 *    The following, modified, code was used https://dior.ics.muni.cz/~velan/flowmon-export-ipfix/
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
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

#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <endian.h>
#include <config.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "flowcacheplugin.h"
#include "flowexporter.h"
#include "ipfixexporter.h"
#include "flowifc.h"
#include "ipfix-elements.h"
#include "byte-utils.h"

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
#define IPFIX_FILL_FIELD(TARGET, FIELD) do { \
   if (FIELD_LEN(FIELD) == 1) { \
      *((uint8_t *) TARGET) = *((uint8_t *) FIELD_SOURCE(FIELD)); \
   } else if (FIELD_LEN(FIELD) == 2) { \
      *((uint16_t *) TARGET) = htons(*((uint16_t *) FIELD_SOURCE(FIELD))); \
   } else if ((FIELD_EN(FIELD) == 0) && \
              ((FIELD_ID(FIELD) == FIELD_ID(L3_IPV4_ADDR_SRC)) || (FIELD_ID(FIELD) == FIELD_ID(L3_IPV4_ADDR_DST)))) { \
      *((uint32_t *) TARGET) = *((uint32_t *) FIELD_SOURCE(FIELD)); \
   } else if (FIELD_LEN(FIELD) == 4) { \
      *((uint32_t *) TARGET) = htonl(*((uint32_t *) FIELD_SOURCE(FIELD))); \
   } else if (FIELD_LEN(FIELD) == 8) { \
      *((uint64_t *) TARGET) = swap_uint64(*((uint64_t *) FIELD_SOURCE(FIELD))); \
   } else { \
      memcpy(TARGET, (void *) FIELD_SOURCE(FIELD), FIELD_LEN(FIELD)); \
   } \
   TARGET += FIELD_LEN(FIELD); \
} while (0)

/*
 * IPFIX template fields.
 *
 * name enterprise-number element-id length
 */
template_file_record_t ipfix_fields[][1] = {
   IPFIX_ENABLED_TEMPLATES(X)
   NULL
};

/* Basic IPv4 template. */
const char *basic_tmplt_v4[] = {
   BASIC_TMPLT_V4(IPFIX_FIELD_NAMES)
   NULL
};

/* Basic IPv6 template. */
const char *basic_tmplt_v6[] = {
   BASIC_TMPLT_V6(IPFIX_FIELD_NAMES)
   NULL
};

IPFIXExporter::IPFIXExporter()
{
   flows_seen = 0;
   flows_dropped = 0;
   templates = NULL;
   templatesDataSize = 0;
   basic_ifc_num = -1;
   verbose = false;

   sequenceNum = 0;
   exportedPackets = 0;
   fd = -1;
   addrinfo = NULL;

   host = "";
   port = "";
   protocol = IPPROTO_TCP;
   ip = AF_UNSPEC; //AF_INET;
   flags = 0;
   reconnectTimeout = RECONNECT_TIMEOUT;
   lastReconnect = 0;
   odid = 0;
   templateRefreshTime = TEMPLATE_REFRESH_TIME;
   templateRefreshPackets = TEMPLATE_REFRESH_PACKETS;
   dir_bit_field = 0;
   packetDataBuffer = NULL;
}

IPFIXExporter::~IPFIXExporter()
{
   shutdown();
}

/**
 * \brief Function called at exporter shutdown
 */
void IPFIXExporter::shutdown()
{
   /* Close the connection */
   if (fd != -1) {
      flush();

      close(fd);
      freeaddrinfo(addrinfo);
      fd = -1;
   }

   template_t *tmp = templates;
   while (tmp != NULL) {
      templates = templates->next;
      free(tmp->buffer);
      free(tmp);
      tmp = templates;
   }
   tmp = NULL;

   free(packetDataBuffer);
   packetDataBuffer = NULL;
}

static_assert(EXTENSION_CNT <= 64, "Extension count is supported up to 64 extensions for now.");
uint64_t IPFIXExporter::get_template_id(Record &flow)
{
   RecordExt *ext = flow.exts;
   uint64_t tmpltIdx = 0;
   while (ext != NULL) {
      tmpltIdx |= ((uint64_t) 1 << ext->extType);
      ext = ext->next;
   }

   return tmpltIdx;
}

std::vector<const char *> IPFIXExporter::get_template_fields(uint64_t tmpltId)
{
   std::vector<const char *> fields;
   uint64_t mask = 1;
   int i = 0;
   while (mask <= tmpltId) {
      if (tmpltId & mask) {
         const char **field = templateFields[i];
         while (*field != NULL) {
            fields.push_back(*field);
            field++;
         }
      }
      mask <<= 1;
      i++;
   }
   fields.push_back(NULL);
   return fields;
}

template_t *IPFIXExporter::get_template(Flow &flow)
{
   int ipTmpltIdx = flow.ip_version == 6 ? TMPLT_IDX_V6 : TMPLT_IDX_V4;
   uint64_t tmpltIdx = get_template_id(flow);
   if (tmpltMap[ipTmpltIdx].find(tmpltIdx) == tmpltMap[ipTmpltIdx].end()) {
      std::vector<const char *> fields = get_template_fields(tmpltIdx);
      tmpltMap[TMPLT_IDX_V4][tmpltIdx] = create_template(basic_tmplt_v4, fields.data());
      tmpltMap[TMPLT_IDX_V6][tmpltIdx] = create_template(basic_tmplt_v6, fields.data());
   }

   return tmpltMap[ipTmpltIdx][tmpltIdx];
}

int fill_extensions(RecordExt *ext, uint8_t *buffer, int size)
{
   RecordExt *extensions[EXTENSION_CNT] = {0};
   int length = 0;
   int extCnt = 0;
   while (ext != NULL) {
      extensions[ext->extType] = ext;
      extCnt++;
      ext = ext->next;
   }
   // TODO: export multiple extension header of same type
   for (unsigned i = 0; i < EXTENSION_CNT; i++) {
      if (extensions[i] == NULL) {
         continue;
      }
      int length_ext = extensions[i]->fillIPFIX(buffer + length, size - length);
      if (length_ext < 0) {
         return -1;
      }
      length += length_ext;
   }
   return length;
}

bool IPFIXExporter::fill_template(Flow &flow, template_t *tmplt)
{
   RecordExt *ext = flow.exts;
   int length = 0;

   if (basic_ifc_num >= 0 && ext == NULL) {
      length = fill_basic_flow(flow, tmplt);
      if (length < 0) {
         return false;
      }
   } else {
      length = fill_basic_flow(flow, tmplt);
      if (length < 0) {
         return false;
      }

      int ext_written = fill_extensions(ext, tmplt->buffer + tmplt->bufferSize + length, tmpltMaxBufferSize - tmplt->bufferSize - length);
      if (ext_written < 0) {
         return false;
      }
      length += ext_written;
   }

   tmplt->bufferSize += length;
   tmplt->recordCount++;
   return true;
}

int IPFIXExporter::export_flow(Flow &flow)
{
   flows_seen++;
   template_t *tmplt = get_template(flow);
   if (!fill_template(flow, tmplt)) {
      flush();

      if (!fill_template(flow, tmplt)) {
         flows_dropped++;
         return 1;
      }
   }
   return 0;
}

/**
 * \brief Exporter initialization
 *
 * @param params plugins Flowcache export plugins.
 * @param basic_num Index of basic pseudoplugin
 * @param odid Exporter identification
 * @param host Collector address
 * @param port Collector port
 * @param udp Use UDP instead of TCP
 * @param mtu Size of packet payload sent
 * @return Returns 0 on succes, non 0 otherwise.
 */
int IPFIXExporter::init(const vector<FlowCachePlugin *> &plugins, int basic_num, uint32_t odid, string host, string port,
   bool udp, uint16_t mtu, bool verbose, uint8_t dir)
{
   int ret;

   if (verbose) {
      fprintf(stderr, "VERBOSE: IPFIX export plugin init start\n");
   }

   /* Init plugin configuration */
   this->verbose = verbose;
   this->host = host;
   this->port = port;
   this->odid = odid;
   this->mtu = mtu;
   basic_ifc_num = basic_num;
   this->dir_bit_field = dir;

   if (mtu <= IPFIX_HEADER_SIZE) {
      fprintf(stderr, "Error: IPFIX message MTU should be at least %d bytes\n", IPFIX_HEADER_SIZE);
      return 1;
   }

   tmpltMaxBufferSize = mtu - IPFIX_HEADER_SIZE;
   packetDataBuffer = (uint8_t *) malloc(sizeof(uint8_t) * mtu);
   if (!packetDataBuffer) {
      return 1;
   }

   if (udp) {
      protocol = IPPROTO_UDP;
   }

   for (int i = 0; i < EXTENSION_CNT; i++) {
      templateFields[i] = NULL;
   }
   for (unsigned int i = 0; i < plugins.size(); i++) {
      FlowCachePlugin * const tmp = plugins[i];
      const vector<plugin_opt> &opts = tmp->get_options();
      templateFields[opts[0].ext_type] = tmp->get_ipfix_string();
   }

   ret = connect_to_collector();
   if (ret == 1) {
      return 1;
   } else if (ret == 2) {
      lastReconnect = time(NULL);
   }

   if (verbose) {
      fprintf(stderr, "VERBOSE: IPFIX export plugin init end\n");
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
void IPFIXExporter::init_template_buffer(template_t *tmpl)
{
   *((uint16_t *) &tmpl->buffer[0]) = htons(tmpl->id);
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
int IPFIXExporter::fill_template_set_header(uint8_t *ptr, uint16_t size)
{
   ipfix_template_set_header_t *header = (ipfix_template_set_header_t *) ptr;

   header->id = htons(TEMPLATE_SET_ID);
   header->length = htons(size);

   return IPFIX_SET_HEADER_SIZE;
}

/**
 * \brief Check whether timeouts for template expired and set exported flag accordingly
 *
 * @param tmpl Template to check
 */
void IPFIXExporter::check_template_lifetime(template_t *tmpl)
{
   if (templateRefreshTime != 0 &&
         (time_t) (templateRefreshTime + tmpl->exportTime) <= time(NULL)) {
      if (verbose) {
         fprintf(stderr, "VERBOSE: Template %i refresh time expired (%is)\n", tmpl->id, templateRefreshTime);
      }
      tmpl->exported = 0;
   }

   if (templateRefreshPackets != 0 &&
         templateRefreshPackets + tmpl->exportPacket <= exportedPackets) {
      if (verbose) {
         fprintf(stderr, "VERBOSE: Template %i refresh packets expired (%i packets)\n", tmpl->id, templateRefreshPackets);
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
int IPFIXExporter::fill_ipfix_header(uint8_t *ptr, uint16_t size)
{
   ipfix_header_t *header = (ipfix_header_t *)ptr;

   header->version = htons(IPFIX_VERISON);
   header->length = htons(size);
   header->exportTime = htonl(time(NULL));
   header->sequenceNumber = htonl(sequenceNum);
   header->observationDomainId = htonl(odid);

   return IPFIX_HEADER_SIZE;
}

/**
 * \brief Get template record from template file by name
 *
 * @param name Name of the record to find
 * @return Template File Record with matching name or NULL when non exists
 */
template_file_record_t *IPFIXExporter::get_template_record_by_name(const char *name)
{
   template_file_record_t *tmpFileRecord = *ipfix_fields;

   if (name == NULL) {
      if (verbose) {
         fprintf(stderr, "VERBOSE: Cannot get template for NULL name\n");
      }
      return NULL;
   }

   while (tmpFileRecord && tmpFileRecord->name) {
      if (strcmp(name, tmpFileRecord->name) == 0) {
         return tmpFileRecord;
      }
      tmpFileRecord++;
   }

   return NULL;
}

/**
 * \brief Set all templates as expired
 */
void IPFIXExporter::expire_templates()
{
   template_t *tmp;
   for (tmp = templates; tmp != NULL; tmp = tmp->next) {
      tmp->exported = 0;
      if (protocol == IPPROTO_UDP) {
         tmp->exportTime = time(NULL);
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
 * @return Created template on success, NULL otherwise
 */
template_t *IPFIXExporter::create_template(const char **tmplt, const char **ext)
{
   uint16_t maxID = FIRST_TEMPLATE_ID;
   uint16_t len;
   template_t *tmpTemplate = templates;
   template_t *newTemplate;
   const char **tmp = tmplt;

   /* Create new template structure */
   newTemplate = (template_t *) malloc(sizeof(template_t));
   if (!newTemplate) {
      fprintf(stderr, "Error: Not enough memory for IPFIX template.\n");
      return NULL;
   }

   newTemplate->fieldCount = 0;
   newTemplate->recordCount = 0;
   newTemplate->buffer = (uint8_t *) malloc(sizeof(uint8_t) * tmpltMaxBufferSize);
   if (!newTemplate->buffer) {
      free(newTemplate);
      fprintf(stderr, "Error: Not enough memory for IPFIX template buffer.\n");
      return NULL;
   }

   /* Set template ID to maximum + 1 */
   while (tmpTemplate != NULL) {
      if (tmpTemplate->id >= maxID) maxID = tmpTemplate->id + 1;
      tmpTemplate = tmpTemplate->next;
   }
   newTemplate->id = maxID;
   ((uint16_t *) newTemplate->templateRecord)[0] = htons(newTemplate->id);

   if (verbose) {
      fprintf(stderr, "VERBOSE: Creating new template id %u\n", newTemplate->id);
   }

   /* Template header size */
   newTemplate->templateSize = 4;

   while (1) {
      while (tmp && *tmp) {
         assert(newTemplate->templateSize + 8u < sizeof(newTemplate->templateRecord));
         /* Find appropriate template file record */
         template_file_record_t *tmpFileRecord = get_template_record_by_name(*tmp);
         if (tmpFileRecord != NULL) {
            if (verbose) {
               fprintf(stderr, "VERBOSE: Adding template field name=%s EN=%u ID=%u len=%d\n",
                  tmpFileRecord->name, tmpFileRecord->enterpriseNumber, tmpFileRecord->elementID, tmpFileRecord->length);
            }

            /* Set information element ID */
            uint16_t eID = tmpFileRecord->elementID;
            if (tmpFileRecord->enterpriseNumber != 0) {
               eID |= 0x8000;
            }
            *((uint16_t *) &newTemplate->templateRecord[newTemplate->templateSize]) = htons(eID);

            /* Set element length */
            if (tmpFileRecord->length == 0) {
               fprintf(stderr, "Error: Template field cannot be zero length.\n");
               free(newTemplate);
               return NULL;
            } else {
               len = tmpFileRecord->length;
            }
            *((uint16_t *) &newTemplate->templateRecord[newTemplate->templateSize + 2]) = htons(len);

            /* Update template size */
            newTemplate->templateSize += 4;

            /* Add enterprise number if required */
            if (tmpFileRecord->enterpriseNumber != 0) {
               *((uint32_t *) &newTemplate->templateRecord[newTemplate->templateSize]) =
                  htonl(tmpFileRecord->enterpriseNumber);
               newTemplate->templateSize += 4;
            }

            /* Increase field count */
            newTemplate->fieldCount++;
         } else {
            fprintf(stderr, "Error: Cannot find field specification for name %s\n", *tmp);
            free(newTemplate);
            return NULL;
         }

         tmp++;
      }

      if (ext == NULL) {
         break;
      }
      tmp = ext;
      ext = NULL;
   }

   /* Set field count */
   ((uint16_t *) newTemplate->templateRecord)[1] = htons(newTemplate->fieldCount);

   /* Initialize buffer for records */
   init_template_buffer(newTemplate);

   /* Update total template size */
   templatesDataSize += newTemplate->bufferSize;

   /* The template was not exported yet */
   newTemplate->exported = 0;
   newTemplate->exportTime = time(NULL);
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
 * @return IPFIX packet with templates to export or NULL on failure
 */
uint16_t IPFIXExporter::create_template_packet(ipfix_packet_t *packet)
{
   template_t *tmp = templates;
   uint16_t totalSize = 0;
   uint8_t *ptr;

   /* Get total size */
   while (tmp != NULL) {
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
   packet->data = (uint8_t *) malloc(sizeof(uint8_t)*(totalSize));
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
   while (tmp != NULL) {
      if (tmp->exported == 0) {
         memcpy(ptr, tmp->templateRecord, tmp->templateSize);
         ptr += tmp->templateSize;
         /* Set the templates as exported, store time and serial number */
         tmp->exported = 1;
         tmp->exportTime = time(NULL);
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
uint16_t IPFIXExporter::create_data_packet(ipfix_packet_t *packet)
{
   template_t *tmp = templates;
   uint16_t totalSize = IPFIX_HEADER_SIZE; /* Include IPFIX header to total size */
   uint32_t deltaSequenceNum = 0; /* Number of exported records in this packet */
   uint8_t *ptr;

   /* Start adding data after the header */
   ptr = packet->data + totalSize;

   /* Copy the data sets to the packet */
   templatesDataSize = 0; /* Erase total data size */
   while (tmp != NULL) {
      /* Add only templates with data that fits to one packet */
      if (tmp->recordCount > 0 && totalSize + tmp->bufferSize <= mtu) {
         memcpy(ptr, tmp->buffer, tmp->bufferSize);
         /* Set SET length */
         ((ipfix_template_set_header_t *) ptr)->length = htons(tmp->bufferSize);
         if (verbose) {
            fprintf(stderr, "VERBOSE: Adding template %i of length %i to data packet\n", tmp->id, tmp->bufferSize);
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
      if (send_packet(&pkt) == 1) {
         /* Collector reconnected, resend the packet */
         send_packet(&pkt);
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
int IPFIXExporter::send_packet(ipfix_packet_t *packet)
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
      ret = sendto(fd, (void *) (packet->data + sent), packet->length - sent, 0,
            addrinfo->ai_addr, addrinfo->ai_addrlen);

      /* Check that the data were sent correctly */
      if (ret == -1) {
         switch (errno) {
         case 0: break; /* OK */
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
            close(fd);
            fd = -1;
            freeaddrinfo(addrinfo);

            /* Set last connection try time so that we would reconnect immediatelly */
            lastReconnect = 1;

            /* Reset the sequences number since it is unique per connection */
            sequenceNum = 0;
            ((ipfix_header_t *) packet->data)->sequenceNumber = 0; /* no need to change byteorder of 0 */

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
      fprintf(stderr, "VERBOSE: Packet (%" PRIu64 ") sent to %s on port %s. Next sequence number is %i\n",
            exportedPackets, host.c_str(), port.c_str(), sequenceNum);
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

   err = getaddrinfo(host.c_str(), port.c_str(), &hints, &addrinfo);
   if (err) {
      if (err == EAI_SYSTEM) {
         fprintf(stderr, "Cannot get server info: %s\n", strerror(errno));
      } else {
         fprintf(stderr, "Cannot get server info: %s\n", gai_strerror(err));
      }
      return 1;
   }

   /* Try addrinfo strucutres one by one */
   for (tmp = addrinfo; tmp != NULL; tmp = tmp->ai_next) {
      if (tmp->ai_family != AF_INET && tmp->ai_family != AF_INET6) {
         continue;
      }

      /* Print information about target address */
      char buff[INET6_ADDRSTRLEN];
      inet_ntop(tmp->ai_family,
            (tmp->ai_family == AF_INET) ?
                  (void *) &((struct sockaddr_in *) tmp->ai_addr)->sin_addr :
                  (void *) &((struct sockaddr_in6 *) tmp->ai_addr)->sin6_addr,
            (char *) &buff, sizeof(buff));

      if (verbose) {
         fprintf(stderr, "VERBOSE: Connecting to IP %s\n", buff);
         fprintf(stderr, "VERBOSE: Socket configuration: AI Family: %i, AI Socktype: %i, AI Protocol: %i\n",
               tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
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
      if (protocol != IPPROTO_UDP &&
            connect(fd, tmp->ai_addr, tmp->ai_addrlen) == -1) {
         if (verbose) {
            perror("VERBOSE: Cannot connect to collector");
         }
         close(fd);
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
   if (tmp == NULL) {
      /* Free allocated resources */
      freeaddrinfo(addrinfo);
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
      if ((time_t) (lastReconnect + reconnectTimeout) <= time(NULL)) {
         /* Try to reconnect */
         if (connect_to_collector() == 0) {
            lastReconnect = 0;
            /* Resend all templates */
            expire_templates();
            send_templates();
         } else {
            /* Set new reconnect time and drop packet */
            lastReconnect = time(NULL);
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


#define GENERATE_FILL_FIELDS_V4() do { \
BASIC_TMPLT_V4(GEN_FILLFIELDS_INT) \
} while (0)

#define GENERATE_FILL_FIELDS_V6() do { \
BASIC_TMPLT_V6(GEN_FILLFIELDS_INT) \
} while (0)

#define GENERATE_FIELDS_SUMLEN(TMPL) TMPL(GEN_FIELDS_SUMLEN_INT) 0

/**
 * \brief Fill template buffer with flow.
 * @param flow Flow
 * @param tmplt Template containing buffer
 * @return Number of written bytes or -1 if buffer is not big enough
 */
int IPFIXExporter::fill_basic_flow(Flow &flow, template_t *tmplt)
{
   uint8_t *buffer, *p;
   int length;
   uint64_t temp;

   buffer = tmplt->buffer + tmplt->bufferSize;
   p = buffer;
   if (flow.ip_version == 4) {
      if (tmplt->bufferSize + GENERATE_FIELDS_SUMLEN(BASIC_TMPLT_V4) > tmpltMaxBufferSize) {
         return -1;
      }

      /* Temporary disable warnings about breaking string-aliasing, since it is produced by
       * if-branches that are never going to be used - generated by C-preprocessor.
       */
#if GCC_CHECK_PRAGMA
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif
		/* Generate code for copying values of IPv4 template into IPFIX message. */
      GENERATE_FILL_FIELDS_V4();
#if GCC_CHECK_PRAGMA
# pragma GCC diagnostic pop
#endif

   } else {
      if (tmplt->bufferSize + GENERATE_FIELDS_SUMLEN(BASIC_TMPLT_V6) > tmpltMaxBufferSize) {
         return -1;
      }

      /* Temporary disable warnings about breaking string-aliasing, since it is produced by
       * if-branches that are never going to be used - generated by C-preprocessor.
       */
#if GCC_CHECK_PRAGMA
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif
		/* Generate code for copying values of IPv6 template into IPFIX message. */
      GENERATE_FILL_FIELDS_V6();
#if GCC_CHECK_PRAGMA
# pragma GCC diagnostic pop
#endif
   }

   length = p - buffer;

   return length;
}
