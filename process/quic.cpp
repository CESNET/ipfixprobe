/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021-2022, CESNET z.s.p.o.
 */

/**
 * \file quic.cpp
 * \brief Plugin for enriching flows for quic data.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \date 2022
 */


#ifdef WITH_NEMEA
# include <unirec/unirec.h>
#endif


#include "quic.hpp"

namespace ipxp {
int RecordExtQUIC::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("quic", [](){
         return new QUICPlugin();
      });

   register_plugin(&rec);
   RecordExtQUIC::REGISTERED_ID = register_extension();
}

QUICPlugin::QUICPlugin()
{
}

QUICPlugin::~QUICPlugin()
{
   close();
}

void QUICPlugin::init(const char *params)
{ }

void QUICPlugin::close()
{

}

ProcessPlugin *QUICPlugin::copy()
{
   return new QUICPlugin(*this);
}



void QUICPlugin::set_stored_cid_fields(RecordExtQUIC *quic_data, RecordExtQUIC *ext) {
    if ((ext != nullptr) && (ext->dir_dport != 0)) {
        if (ext->dir_dport == quic_data->server_port) {
            // to server
            quic_data->scid_length = ext->dir_dcid_length;
            memcpy(quic_data->scid, ext->dir_dcid, quic_data->scid_length);
            quic_data->occid_length = ext->dir_scid_length;
            memcpy(quic_data->occid, ext->dir_scid, quic_data->occid_length);
        } else {
            // from server
            quic_data->scid_length = ext->dir_scid_length;
            memcpy(quic_data->scid, ext->dir_scid, quic_data->scid_length);
            quic_data->occid_length = ext->dir_dcid_length;
            memcpy(quic_data->occid, ext->dir_dcid, quic_data->occid_length);
        }
        ext->dir_dport = 0;
    }
}


void QUICPlugin::set_cid_fields(RecordExtQUIC *quic_data, QUICParser *process_quic, int toServer,
                                RecordExtQUIC *ext, const Packet &pkt  ) {
    switch (toServer) {
        case 1:
            process_quic->quic_get_dcid(quic_data->scid);
            process_quic->quic_get_dcid_len(quic_data->scid_length);

            process_quic->quic_get_scid(quic_data->occid);
            process_quic->quic_get_scid_len(quic_data->occid_length);

            set_stored_cid_fields(quic_data, ext);
            break;
        case 0:
            process_quic->quic_get_dcid(quic_data->occid);
            process_quic->quic_get_dcid_len(quic_data->occid_length);

            process_quic->quic_get_scid(quic_data->scid);
            process_quic->quic_get_scid_len(quic_data->scid_length);

            set_stored_cid_fields(quic_data, ext);
            break;
        case -1:
        default:
            // no direction information, store for future use
            process_quic->quic_get_scid(quic_data->dir_scid);
            process_quic->quic_get_scid_len(quic_data->dir_scid_length);
            process_quic->quic_get_dcid(quic_data->dir_dcid);
            process_quic->quic_get_dcid_len(quic_data->dir_dcid_length);
            quic_data->dir_dport = pkt.dst_port;
            break;
    }
}


int QUICPlugin::get_direction_to_server_and_set_port(QUICParser *process_quic, RecordExtQUIC *quic_data,
                                                     uint16_t parsed_port, const Packet &pkt, RecordExtQUIC *ext) {
    int toServer = get_direction_to_server(parsed_port, pkt, ext);
    if ((toServer != -1) && (quic_data->server_port ==0)) {
        quic_data->server_port = process_quic->quic_get_server_port();
    }
    return toServer;
}

int QUICPlugin::get_direction_to_server(uint16_t parsed_port, const Packet &pkt, RecordExtQUIC *ext)
{
    if (parsed_port != 0) {
        return pkt.dst_port == parsed_port;
    } else if (((ext != nullptr) && (ext->server_port != 0))) {
        return pkt.dst_port == ext->server_port;
    }
    return -1;
}

void QUICPlugin::set_client_hello_fields(QUICParser *process_quic, RecordExtQUIC *quic_data, const Packet &pkt,
                                         RecordExtQUIC *ext) {

    process_quic->quic_get_token_length(quic_data->quic_token_length);
    char dcid[MAX_CID_LEN] = { 0 };
    uint8_t dcid_len = 0;
    // since this this is a client hello the dcid must be set
    process_quic->quic_get_dcid(dcid);
    process_quic->quic_get_dcid_len(dcid_len);




    if ((quic_data->quic_token_length != QUICParser::QUIC_CONSTANTS::QUIC_UNUSED_VARIABLE_LENGTH_INT) &&
        (quic_data->quic_token_length > 0) &&
        ((quic_data->retry_scid_length == dcid_len) ||
        (ext != nullptr) && (ext->retry_scid_length == dcid_len)) &&
        ((strncmp(quic_data->retry_scid, dcid, std::min(quic_data->retry_scid_length, dcid_len)) == 0) ||
        ((ext != nullptr) && (strncmp(ext->retry_scid, dcid, std::min(ext->retry_scid_length, dcid_len))) == 0) ) ) {
        // Retry case: We already have all information from the previous CH.

    } else {
        // MULTIPLEXING detection
        char oscid[MAX_CID_LEN] = { 0 };
        uint8_t oscid_len = 0;
        process_quic->quic_get_dcid(oscid);
        process_quic->quic_get_dcid_len(oscid_len);

        char sni[BUFF_SIZE] = { 0 };
        process_quic->quic_get_sni(sni);

        if (( (oscid_len == quic_data->oscid_length) &&
              (quic_data->oscid_length != 0) &&
              (strncmp(oscid, quic_data->oscid, oscid_len) == 0) &&
              (strncmp(quic_data->sni, sni, BUFF_SIZE )) == 0) ||
            ((ext == nullptr))) {
            // Repeated Initial or new Initial/QUIC flow
            quic_data->server_port = process_quic->quic_get_server_port();

            process_quic->quic_get_sni(quic_data->sni);
            process_quic->quic_get_user_agent(quic_data->user_agent);

            process_quic->quic_get_dcid(quic_data->oscid);
            process_quic->quic_get_dcid_len(quic_data->oscid_length);

            process_quic->quic_get_scid(quic_data->occid);
            process_quic->quic_get_scid_len(quic_data->occid_length);

            // Set client version to extract difference in compatible version negotiation: RFC9368
            process_quic->quic_get_version(quic_data->quic_client_version);
        } else {
            if (quic_data->quic_multiplexed < 0xFF) {
                quic_data->quic_multiplexed += 1;
            }
        }
    }
}


int QUICPlugin::process_quic(RecordExtQUIC *quic_data, Flow &rec, const Packet &pkt)
{
   QUICParser process_quic;

   // Test for QUIC packet in UDP payload
   if(process_quic.quic_check_quic_long_header_packet(pkt) ) {

       process_quic.quic_get_version(quic_data->quic_version);
       if (quic_data->quic_version == QUICParser::QUIC_VERSION::version_negotiation) {
           return FLOW_FLUSH;
       }

       RecordExtQUIC *ext = (RecordExtQUIC *) rec.get_extension(RecordExtQUIC::REGISTERED_ID);
       // Simple version, more advanced information is available after Initial parsing
       int toServer = get_direction_to_server_and_set_port(&process_quic, quic_data, process_quic.quic_get_server_port(), pkt, ext);

       uint8_t packets = 0;
       process_quic.quic_get_packets(packets);
        if (packets & QUICParser::PACKET_TYPE_FLAG::F_ZERO_RTT) {
            uint8_t zero_rtt_pkts = process_quic.quic_get_zero_rtt();

            if ((uint16_t) zero_rtt_pkts + (uint16_t)quic_data->quic_zero_rtt > 0xFF) {
                quic_data->quic_zero_rtt = 0xFF;
            } else {
                quic_data->quic_zero_rtt += zero_rtt_pkts;
            }
        }
       uint8_t parsed_initial = 0;

       switch (process_quic.quic_get_packet_type()) {
           case QUICParser::PACKET_TYPE::INITIAL:
               process_quic.quic_get_parsed_initial(parsed_initial);
               if (parsed_initial) {
                   // Successful CH parsing
                   set_client_hello_fields(&process_quic, quic_data, pkt, ext);
                   break;
               }
               // Update accounting for information from CH, SH.
               toServer = get_direction_to_server_and_set_port(&process_quic, quic_data, process_quic.quic_get_server_port(), pkt, ext);
               // fallthrough to set cids
           case QUICParser::PACKET_TYPE::ZERO_RTT:
           case QUICParser::PACKET_TYPE::HANDSHAKE:
               // -1 sets stores intermediately.
               set_cid_fields(quic_data, &process_quic, toServer, ext, pkt);
               break;
           case QUICParser::PACKET_TYPE::RETRY:
               // Additionally set token len
               process_quic.quic_get_scid(quic_data->retry_scid);
               process_quic.quic_get_scid_len(quic_data->retry_scid_length);
               process_quic.quic_get_token_length(quic_data->quic_token_length);
               set_cid_fields(quic_data, &process_quic, toServer, ext, pkt);
               break;
       }

       return QUIC_DETECTED;
   }
   return QUIC_NOT_DETECTED;
} // QUICPlugin::process_quic

int QUICPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int QUICPlugin::post_create(Flow &rec, const Packet &pkt)
{
   return add_quic(rec, pkt);
}

int QUICPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int QUICPlugin::post_update(Flow &rec, const Packet &pkt)
{
   RecordExtQUIC *ext = (RecordExtQUIC *) rec.get_extension(RecordExtQUIC::REGISTERED_ID);

   if (ext == nullptr) {
      return 0;
   }

   return add_quic(rec, pkt);
}

int QUICPlugin::add_quic(Flow &rec, const Packet &pkt)
{
   RecordExtQUIC *q_ptr = (RecordExtQUIC *) rec.get_extension(RecordExtQUIC::REGISTERED_ID);
   bool new_qptr = false;
   if (q_ptr == nullptr) {
      new_qptr = true;
      q_ptr = new RecordExtQUIC();
   }

   int ret = process_quic(q_ptr, rec, pkt);
   // Test if QUIC extension is not set
   if (new_qptr && (ret == QUIC_DETECTED)) {
         rec.add_extension(q_ptr);
   }
   if (new_qptr && (ret == QUIC_NOT_DETECTED)) {
      // If still no record delete q_ptr
      delete q_ptr;
   }
   // Correct if QUIC has already been detected
   if (!new_qptr && (ret == QUIC_NOT_DETECTED)) {
       return QUIC_DETECTED;
   }
   return ret;
}

void QUICPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "QUIC plugin stats:" << std::endl;
      std::cout << "   Parsed SNI: " << parsed_initial << std::endl;
   }
}
}
