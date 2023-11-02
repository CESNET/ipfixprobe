/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021-2022, CESNET z.s.p.o.
 */

/**
 * \file quic.hpp
 * \brief Plugin for enriching flows for quic data.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \date 2022
 */


#ifndef IPXP_PROCESS_QUIC_HPP
#define IPXP_PROCESS_QUIC_HPP


#ifdef WITH_NEMEA
# include "fields.h"
#endif


#include "quic_parser.hpp"
#include <ipfixprobe/utils.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <sstream>


namespace ipxp {
#define QUIC_UNIREC_TEMPLATE "QUIC_SNI,QUIC_USER_AGENT,QUIC_VERSION,QUIC_CLIENT_VERSION,QUIC_TOKEN_LENGTH,QUIC_OCCID,QUIC_OSCID,QUIC_SCID,QUIC_RETRY_SCID,QUIC_MULTIPLEXED,QUIC_ZERO_RTT,QUIC_PACKETS"
UR_FIELDS(
   string QUIC_SNI,
   string QUIC_USER_AGENT,
   uint32 QUIC_VERSION,
   uint32 QUIC_CLIENT_VERSION,
   uint64 QUIC_TOKEN_LENGTH,
   bytes QUIC_OCCID,
   bytes QUIC_OSCID,
   bytes QUIC_SCID,
   bytes QUIC_RETRY_SCID,
   uint8 QUIC_MULTIPLEXED,
   uint8 QUIC_ZERO_RTT,
   uint8* QUIC_PACKETS
)

/**
 * \brief Flow record extension header for storing parsed QUIC packets.
 */
#define QUIC_MAX_ELEMCOUNT 30
#define MAX_CID_LEN 20
#define QUIC_DETECTED 0
#define QUIC_NOT_DETECTED 2
#define QUIC_PKT_FIELD_ID 888

struct RecordExtQUIC : public RecordExt {
   static int REGISTERED_ID;
   char       sni[BUFF_SIZE]        = { 0 };
   char       user_agent[BUFF_SIZE] = { 0 };
   uint32_t   quic_version;
   uint32_t   quic_client_version;
   uint64_t   quic_token_length;
   // We use a char as a buffer.
   uint8_t    occid_length;
   uint8_t    oscid_length;
   uint8_t    scid_length;
   uint8_t    dir_scid_length;
   uint8_t    dir_dcid_length;
   uint8_t    retry_scid_length;
   char       occid[MAX_CID_LEN] = { 0 };
   char       oscid[MAX_CID_LEN] = { 0 };
   char       scid[MAX_CID_LEN] = { 0 };
   char       retry_scid[MAX_CID_LEN] = { 0 };
   // Intermediate storage when direction is not clear
   char       dir_scid[MAX_CID_LEN] = { 0 };
   char       dir_dcid[MAX_CID_LEN] = { 0 };
   uint16_t   dir_dport;
   uint16_t   server_port;

   uint8_t    quic_multiplexed;
   uint8_t    quic_zero_rtt;
   uint8_t    pkt_types[QUIC_MAX_ELEMCOUNT];
   uint8_t    last_pkt_type;

   RecordExtQUIC() : RecordExt(REGISTERED_ID)
   {
      sni[0]        = 0;
      user_agent[0] = 0;
      quic_version  = 0;
      quic_client_version  = 0;
      occid_length  = 0;
      oscid_length  = 0;
      scid_length   = 0;
      retry_scid_length = 0;
      occid[0]      = 0;
      oscid[0]      = 0;
      scid[0]       = 0;
      retry_scid[0] = 0;
      dir_dcid[0]   = 0;
      dir_scid[0]   = 0;
      dir_dcid_length=0;
      dir_scid_length=0;
      server_port          = 0;
      dir_dport     = 0;
      quic_token_length = QUICParser::QUIC_CONSTANTS::QUIC_UNUSED_VARIABLE_LENGTH_INT;
      quic_multiplexed = 0;
      quic_zero_rtt = 0;
      memset(pkt_types, 0, sizeof(pkt_types));
      last_pkt_type = 0;
   }

   #ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_QUIC_SNI, sni);
      ur_set_string(tmplt, record, F_QUIC_USER_AGENT, user_agent);
      ur_set(tmplt, record, F_QUIC_VERSION, quic_version);
      ur_set(tmplt, record, F_QUIC_CLIENT_VERSION, quic_client_version);
      ur_set(tmplt, record, F_QUIC_TOKEN_LENGTH, quic_token_length);
      ur_set_var(tmplt, record, F_QUIC_OCCID, occid, occid_length);
      ur_set_var(tmplt, record, F_QUIC_OSCID, oscid, oscid_length);
      ur_set_var(tmplt, record, F_QUIC_SCID, scid, scid_length);
      ur_set_var(tmplt, record, F_QUIC_RETRY_SCID, retry_scid, retry_scid_length);
      ur_set(tmplt, record, F_QUIC_MULTIPLEXED, quic_multiplexed);
      ur_set(tmplt, record, F_QUIC_ZERO_RTT, quic_zero_rtt);
      ur_array_allocate(tmplt, record, F_QUIC_PACKETS, last_pkt_type+1);
      for (int i = 0; i < last_pkt_type+1; i++) {
        ur_array_set(tmplt, record, F_QUIC_PACKETS, i, pkt_types[i]);
      }
   }

   const char *get_unirec_tmplt() const
   {
      return QUIC_UNIREC_TEMPLATE;
   }

   #endif // ifdef WITH_NEMEA

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
       IpfixBasicList basiclist;
       basiclist.hdrEnterpriseNum = IpfixBasicList::CesnetPEM;
      uint16_t len_sni        = strlen(sni);
      uint16_t len_user_agent = strlen(user_agent);
      uint16_t len_version    = sizeof(quic_version);
      uint16_t len_client_version = sizeof(quic_client_version);
      uint16_t len_token_length = sizeof(quic_token_length);
      uint16_t len_multiplexed = sizeof(quic_multiplexed);
      uint16_t len_zero_rtt = sizeof(quic_zero_rtt);
      uint16_t pkt_types_len = sizeof(pkt_types[0])*(last_pkt_type+1) + basiclist.HeaderSize() ;
      uint32_t pos = 0;

      if ((len_sni + 3) + (len_user_agent + 3) + len_version +
            len_client_version + len_token_length + len_multiplexed + len_zero_rtt +
            (scid_length + 3) + (occid_length + 3) + (oscid_length + 3)  + (retry_scid_length + 3) +
            pkt_types_len > size) {
         return -1;
      }

      pos += variable2ipfix_buffer(buffer + pos, (uint8_t *) sni, len_sni);
      pos += variable2ipfix_buffer(buffer + pos, (uint8_t *) user_agent, len_user_agent);
      *(uint32_t *) (buffer + pos) = htonl(quic_version);
      pos += len_version;
       *(uint32_t *) (buffer + pos) = htonl(quic_client_version);
      pos += len_client_version;
      *(uint64_t *) (buffer + pos) = htobe64(quic_token_length);
      pos += len_token_length;
      // original client connection ID
      pos += variable2ipfix_buffer(buffer + pos, (uint8_t *) occid, occid_length);
      // original server connection id
      pos += variable2ipfix_buffer(buffer + pos, (uint8_t *) oscid, oscid_length);
      // server connection id
      pos += variable2ipfix_buffer(buffer + pos, (uint8_t *) scid, scid_length);
      // retry server connection id
      pos += variable2ipfix_buffer(buffer + pos, (uint8_t *) retry_scid, retry_scid_length);

      *(uint8_t *) (buffer + pos) = quic_multiplexed;
      pos += 1;

       *(uint8_t *) (buffer + pos) = quic_zero_rtt;
       pos += 1;
       // Packet types
       pos += basiclist.FillBuffer(buffer + pos, pkt_types, (uint16_t) last_pkt_type + 1, (uint16_t) QUIC_PKT_FIELD_ID);

       return pos;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_QUIC_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };

      return ipfix_template;
   }

   std::string get_text() const
   {
      std::ostringstream out;

      out << "quicsni=\"" << sni << "\"" << "quicuseragent=\"" << user_agent << "\"" << "quicversion=\"" <<
           quic_version << "\""
           << "quicclientversion=\"" << quic_client_version << "\""
           << "quicoccidlength=\"" << occid_length << "\"" << "quicoccid=\"" << occid << "\""
           << "quicoscidlength=\"" << oscid_length << "\"" << "quicoscid=\"" << oscid << "\""
           << "quicscidlength=\"" << scid_length << "\"" << "quicscid=\"" << scid << "\""
           << "quicmultiplexed=\"" << quic_multiplexed << "\""
           << "quiczerortt=\"" << quic_zero_rtt << "\"";
      return out.str();
   }
};

/**
 * \brief Flow cache plugin for parsing QUIC packets.
 */
class QUICPlugin : public ProcessPlugin
{
public:
   QUICPlugin();
   ~QUICPlugin();
   void init(const char *params);
   void close();
   RecordExt *get_ext() const { return new RecordExtQUIC(); }

   OptionsParser *get_parser() const { return new OptionsParser("quic", "Parse QUIC traffic"); }

   std::string get_name() const { return "quic"; }

   ProcessPlugin *copy();

   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   int add_quic(Flow &rec, const Packet &pkt);
   void finish(bool print_stats);

private:
   int process_quic(RecordExtQUIC *, Flow &rec, const Packet&);
   void set_stored_cid_fields(RecordExtQUIC *quic_data, RecordExtQUIC *ext);
   void set_cid_fields(RecordExtQUIC *quic_data, QUICParser *process_quic, int toServer,
                                       RecordExtQUIC *ext, const Packet &pkt );
   int get_direction_to_server(uint16_t parsed_port, const Packet &pkt, RecordExtQUIC *ext);
   int get_direction_to_server_and_set_port(QUICParser *process_quic, RecordExtQUIC *quic_data, uint16_t parsed_port, const Packet &pkt, RecordExtQUIC *ext);
   void set_client_hello_fields(QUICParser *process_quic, RecordExtQUIC *quic_data, const Packet &pkt,
                                         RecordExtQUIC *ext );
   int parsed_initial;
   RecordExtQUIC *quic_ptr;
};
}
#endif /* IPXP_PROCESS_QUIC_HPP */
