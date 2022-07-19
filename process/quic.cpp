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
