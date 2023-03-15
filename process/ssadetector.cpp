/**
 * \file ssadetector.cpp
 * \brief Plugin for detecting ssa sequence.
 * \author Jan Jirák jirakja7@fit.cvut.cz
 * \author Karel Hynek hynekkar@cesnet.cz
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

#include <iostream>

#include "ssadetector.hpp"

namespace ipxp {

int RecordExtSSADetector::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("ssadetector", [](){return new SSADetectorPlugin();});
   register_plugin(&rec);
   RecordExtSSADetector::REGISTERED_ID = register_extension();
}

SSADetectorPlugin::SSADetectorPlugin()
{
}

SSADetectorPlugin::~SSADetectorPlugin()
{
}

void SSADetectorPlugin::init(const char *params)
{
}

void SSADetectorPlugin::close()
{
}

ProcessPlugin *SSADetectorPlugin::copy()
{
   return new SSADetectorPlugin(*this);
}

int SSADetectorPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int SSADetectorPlugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int SSADetectorPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int SSADetectorPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void SSADetectorPlugin::pre_export(Flow &rec)
{
//--------------------RecordExtSSADetector::pkt_entry-------------------------------
void RecordExtSSADetector::pkt_entry::reset() 
{
      ts_dir1.tv_sec = 0;
      ts_dir1.tv_usec = 0;
      ts_dir2.tv_sec = 0;
      ts_dir2.tv_usec = 0;
}

timeval& RecordExtSSADetector::pkt_entry::get_time(dir_t dir)
{
   return (dir == 1)? ts_dir1 : ts_dir2;
}

RecordExtSSADetector::pkt_entry::pkt_entry()
{
   reset();
}

//--------------------RecordExtSSADetector::pkt_table-------------------------------
void RecordExtSSADetector::pkt_table::reset()
{
   for (int i = 0; i < PKT_TABLE_SIZE; ++i) {
         table_[i].reset();
      }
}

bool RecordExtSSADetector::pkt_table::check_range_for_presence(uint16_t len, uint8_t down_by, 
                                                               dir_t dir, const timeval& ts_to_compare)
{
   int8_t idx = get_idx_from_len(len);
   for (int8_t i = std::max(idx - down_by, 0); i <= idx; ++i) {
      if (entry_is_present(i, dir, ts_to_compare)) {
         return true;
      }
   }
   return false;
}

void RecordExtSSADetector::pkt_table::update_entry(uint16_t len, dir_t dir, timeval ts)
{
   int8_t idx = get_idx_from_len(len);
   if (dir == 1) {
      table_[idx].ts_dir1 = ts;
   } else  {
      table_[idx].ts_dir2 = ts;
   }
}

bool RecordExtSSADetector::pkt_table::time_in_window(const timeval& ts_now, const timeval& ts_old)
{
   long diff_secs = ts_now.tv_sec - ts_old.tv_sec;
   long diff_micro_secs = ts_now.tv_usec - ts_old.tv_usec;

   diff_micro_secs += diff_secs * 1000000;
   if (diff_micro_secs > MAX_TIME_WINDOW) { 
      return false;
   }
   return true;
}

bool RecordExtSSADetector::pkt_table::entry_is_present(int8_t idx, dir_t dir, const timeval& ts_to_compare)
{
   timeval& ts = table_[idx].get_time(dir);
   if (time_in_window(ts_to_compare, ts)) {
      return true;
   } 
   return false;
}

int8_t RecordExtSSADetector::pkt_table::get_idx_from_len(uint16_t len)
{
   return std::max(int(len) - MIN_PKT_SIZE, 0);
}

}

