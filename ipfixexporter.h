/**
 * \file ipfixexporter.h
 * \brief Export flows in IPFIX format.
 *    The following code was used https://dior.ics.muni.cz/~velan/flowmon-export-ipfix/
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
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

#ifndef IPFIX_EXPORTER_H
#define IPFIX_EXPORTER_H

#include <vector>

#include "flowcacheplugin.h"
#include "flowexporter.h"
#include "flowifc.h"

using namespace std;

#define TEMPLATE_SET_ID 2
#define FIRST_TEMPLATE_ID 258
#define IPFIX_VERISON 10
#define PACKET_DATA_SIZE 1458 /* ethernet 14, ip 20, udp 8 */
#define IPFIX_HEADER_SIZE 16
#define IPFIX_SET_HEADER_SIZE 4
#define TEMPLATE_BUFFER_SIZE (PACKET_DATA_SIZE - IPFIX_HEADER_SIZE)
#define RECONNECT_TIMEOUT 60
#define TEMPLATE_REFRESH_TIME 600
#define TEMPLATE_REFRESH_PACKETS 0

typedef struct {
	char *name; /**< Record name */
	uint16_t enterpriseNumber; /**< Enterprise Number */
	uint16_t elementID; /**< Information Element ID */
	int32_t length; /**< Element export length. -1 for variable*/
} template_file_record_t;

/**
 * \brief Structure to hold template record
 */
typedef struct template_t {
	uint16_t id; /**< Template ID */
	uint8_t templateRecord[200]; /**< Buffer for template record */
	uint16_t templateSize; /**< Size of template record buffer */
	uint8_t buffer[TEMPLATE_BUFFER_SIZE]; /**< Buffer with data for template */
	uint16_t bufferSize; /**< Size of data buffer */
	uint16_t recordCount; /**< Number of records in buffer */
	uint16_t fieldCount; /**< Number of elements in template */
	uint8_t exported; /**< 1 indicates that the template was exported to collector*/
	time_t exportTime; /**< Time when the template was last exported */
	uint64_t exportPacket; /**< Number of packet when the template was last exported */
	struct template_t *next;
} template_t;

/**
 * \brief Structure of ipfix packet used by send functions
 */
typedef struct {
	char *data; /**< Buffer for data */
	uint16_t length; /**< Length of data */
	uint16_t flows; /**< Number of flow records in the packet */
} ipfix_packet_t;

/**
 * \brief IPFIX header structure
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |       Version Number          |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           Export Time                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Sequence Number                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Observation Domain ID                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
typedef struct ipfix_header {
	/**
	 * Version of Flow Record format exported in this message. The value of this
	 * field is 0x000a for the current version, incrementing by one the version
	 * used in the NetFlow services export version 9.
	 */
	uint16_t version;

	/**
	 * Total length of the IPFIX Message, measured in octets, including Message
	 * Header and Set(s).
	 */
	uint16_t length;

	/**
	 * Time, in seconds, since 0000 UTC Jan 1, 1970, at which the IPFIX Message
	 * Header leaves the Exporter.
	 */
	uint32_t exportTime;

	/**
	 * Incremental sequence counter modulo 2^32 of all IPFIX Data Records sent
	 * on this PR-SCTP stream from the current Observation Domain by the
	 * Exporting Process. Check the specific meaning of this field in the
	 * subsections of Section 10 when UDP or TCP is selected as the transport
	 * protocol. This value SHOULD be used by the Collecting Process to
	 * identify whether any IPFIX Data Records have been missed. Template and
	 * Options Template Records do not increase the Sequence Number.
	 */
	uint32_t sequenceNumber;

	/**
	 * A 32-bit identifier of the Observation Domain that is locally unique to
	 * the Exporting Process. The Exporting Process uses the Observation Domain
	 * ID to uniquely identify to the Collecting Process the Observation Domain
	 * that metered the Flows. It is RECOMMENDED that this identifier also be
	 * unique per IPFIX Device. Collecting Processes SHOULD use the Transport
	 * Session and the Observation Domain ID field to separate different export
	 * streams originating from the same Exporting Process. The Observation
	 * Domain ID SHOULD be 0 when no specific Observation Domain ID is relevant
	 * for the entire IPFIX Message, for example, when exporting the Exporting
	 * Process Statistics, or in case of a hierarchy of Collectors when
	 * aggregated Data Records are exported.
	 */
	uint32_t observationDomainId;
} ipfix_header_t;

/**
 * \brief Common IPFIX Set (header) structure
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Set ID               |          Length               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
typedef struct ipfix_template_set_header {
	/**
	 * Set ID value identifies the Set.  A value of 2 is reserved for the
	 * Template Set. A value of 3 is reserved for the Option Template Set. All
	 * other values from 4 to 255 are reserved for future use. Values above 255
	 * are used for Data Sets. The Set ID values of 0 and 1 are not used for
	 * historical reasons [<a href="http://tools.ietf.org/html/rfc3954">RFC3954</a>].
	 */
	uint16_t id;

	/**
	 * Total length of the Set, in octets, including the Set Header, all
	 * records, and the optional padding.  Because an individual Set MAY contain
	 * multiple records, the Length value MUST be used to determine the position
	 * of the next Set.
	 */
	uint16_t length;

} ipfix_template_set_header_t;

class IPFIXExporter : public FlowExporter
{
public:
   IPFIXExporter();
   ~IPFIXExporter();
   int export_flow(Flow &flow);
   int export_packet(Packet &pkt);
   int init(const vector<FlowCachePlugin *> &plugins, int basic_ifc_num, uint32_t odid, string host, string port, bool udp, bool verbose, uint8_t dir = 1);
   void flush();
   void shutdown();
private:
	/* Templates */
	template_t **templateArray;
	template_t *templates; /**< Templates in use by plugin */
	uint16_t templatesDataSize; /**< Total data size stored in templates */
   int *tmpltMapping;
   int basic_ifc_num;
   bool verbose;

	uint32_t sequenceNum; /**< Number of exported flows */
	uint64_t exportedPackets; /**< Number of exported packets */
	int fd; /**< Socket used to send data */
	struct addrinfo *addrinfo; /**< Info about the connection used by sendto */

	/* Parameters */
	string host; /**< Hostname */
	string port; /**< Port */
	int protocol; /**< Protocol */
	int ip; /**< IP protocol version (AF_INET, ...) */
	int flags; /**< getaddrinfo flags */
	uint32_t reconnectTimeout; /**< Timeout between connection retries */
	time_t lastReconnect; /**< Time in seconds of last connection retry */
	uint32_t odid; /**< Observation Domain ID */
	uint32_t templateRefreshTime; /**< UDP template refresh time interval */
	uint32_t templateRefreshPackets; /**< UDP template refresh packet interval */
   uint8_t dir_bit_field;     /**< Direction bit field value. */

   void init_template_buffer(template_t *tmpl);
   int fill_template_set_header(char *ptr, uint16_t size);
   void check_template_lifetime(template_t *tmpl);
   int fill_ipfix_header(char *ptr, uint16_t size);
   template_file_record_t *get_template_record_by_name(const char *name);
   void expire_templates();
   template_t *create_template(const char **tmplt, const char **ext);
   uint16_t create_template_packet(ipfix_packet_t *packet);
   uint16_t create_data_packet(ipfix_packet_t *packet);
   void send_templates();
   void send_data();
   int send_packet(ipfix_packet_t *packet);
   int connect_to_collector();
   int reconnect();
   int fill_basic_flow(Flow &flow, template_t *tmplt);
   int fill_packet_fields(Packet &pkt, template_t *tmplt);
};

#endif
