/**
 * \file quic.cpp
 * \brief Plugin for parsing quic traffic.
 * \author andrej lukacovic lukacan1@fit.cvut.cz
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided as is'', and any express or implied
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
 *
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
   quic_ptr = nullptr;
}

QUICPlugin::~QUICPlugin()
{
   close();
}

void QUICPlugin::init(const char *params)
{ }

void QUICPlugin::close()
{
   if (quic_ptr != nullptr) {
      delete quic_ptr;
   }
   quic_ptr = nullptr;
}

ProcessPlugin *QUICPlugin::copy()
{
   return new QUICPlugin(*this);
}

bool QUICPlugin::process_quic(RecordExtQUIC *quic_data, const Packet &pkt)
{
   QUICParser process_quic;

   if (!process_quic.quic_start(pkt)) {
      return false;
   } else   {
      process_quic.quic_get_sni(quic_data->sni);
      process_quic.quic_get_user_agent(quic_data->user_agent);
      process_quic.quic_get_version(quic_data->quic_version);
      return true;
   }
} // QUICPlugin::process_quic

int QUICPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int QUICPlugin::post_create(Flow &rec, const Packet &pkt)
{
   add_quic(rec, pkt);
   return 0;
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

   add_quic(rec, pkt);
   return 0;
}

void QUICPlugin::add_quic(Flow &rec, const Packet &pkt)
{
   if (quic_ptr == nullptr) {
      quic_ptr = new RecordExtQUIC();
   }

   if (process_quic(quic_ptr, pkt)) {
      rec.add_extension(quic_ptr);
      quic_ptr = nullptr;
   }
}

void QUICPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "QUIC plugin stats:" << std::endl;
      std::cout << "   Parsed SNI: " << parsed_initial << std::endl;
   }
}
}
