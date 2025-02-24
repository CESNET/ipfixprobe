/**
 * @file
 * @brief Plugin for parsing bstats traffic.
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 * 
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "basicplus.hpp"

namespace ipxp {

int RecordExtBASICPLUS::REGISTERED_ID = register_extension();

static const PluginManifest basicplusPluginManifest = {
   .name = "basicplus",
   .description = "Basicplus process plugin for parsing bstats traffic.",
   .pluginVersion = "1.0.0",
   .apiVersion = "1.0.0",
};

BASICPLUSPlugin::BASICPLUSPlugin(const std::string& params)
{
   init(params.c_str());
}

BASICPLUSPlugin::~BASICPLUSPlugin()
{
   close();
}

void BASICPLUSPlugin::init(const char *params)
{
}

void BASICPLUSPlugin::close()
{
}

ProcessPlugin *BASICPLUSPlugin::copy()
{
   return new BASICPLUSPlugin(*this);
}

int BASICPLUSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtBASICPLUS *p = new RecordExtBASICPLUS();

   rec.add_extension(p);

   p->ip_ttl[0]  = pkt.ip_ttl;
   p->ip_flg[0]  = pkt.ip_flags;
   p->tcp_mss[0] = pkt.tcp_mss;
   p->tcp_opt[0] = pkt.tcp_options;
   p->tcp_win[0] = pkt.tcp_window;
   if (pkt.tcp_flags == 0x02) { // check syn packet
      p->tcp_syn_size = pkt.ip_len;
   }

   return 0;
}

int BASICPLUSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtBASICPLUS *p = (RecordExtBASICPLUS *) rec.get_extension(RecordExtBASICPLUS::REGISTERED_ID);
   uint8_t dir = pkt.source_pkt ? 0 : 1;

   if (p->ip_ttl[dir] < pkt.ip_ttl) {
      p->ip_ttl[dir] = pkt.ip_ttl;
   }
   if (dir && !p->dst_filled) {
      p->ip_ttl[1]  = pkt.ip_ttl;
      p->ip_flg[1]  = pkt.ip_flags;
      p->tcp_mss[1] = pkt.tcp_mss;
      p->tcp_win[1] = pkt.tcp_window;
      p->dst_filled = true;
   }
   // update tcp options mask across the tcp flow
   p->tcp_opt[dir] |= pkt.tcp_options;
   return 0;
}

static const PluginRegistrar<BASICPLUSPlugin, ProcessPluginFactory> basicplusRegistrar(basicplusPluginManifest);

}
