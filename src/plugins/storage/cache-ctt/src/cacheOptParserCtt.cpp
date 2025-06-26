/**
* \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief CacheOptParser implementation.
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
 */

#include "cacheOptParserCtt.hpp"

#include <ipfixprobe/cttmeta.hpp>
#include <ipfixprobe/utils.hpp>
#include <cstring>

namespace ipxp {

CacheOptParserCtt::CacheOptParserCtt()
   : CacheOptParser("cache-ctt", "Storage plugin implemented as a hash table with support of ctt-offload")
   {
      register_option("m", "mode", "MODE", "none/drop/trim",
         [this](const char *arg){
            if (strcmp(arg, "none") == 0) {
               m_offload_mode = std::nullopt;
            } else if (strcmp(arg, "drop") == 0) {
               m_offload_mode = feta::OffloadMode::DROP_PACKET_DROP_META;
            } else if (strcmp(arg, "trim") == 0) {
               m_offload_mode = feta::OffloadMode::TRIM_PACKET_META;
            } else {
               return false;
            }
            return true;
         },
         OptionFlags::RequiredArgument);
      register_option("ot", "offload-threshold", "count", "Flow is ctt offloaded if count of packets is more than threshold. Must be at least 0. Default is 1000.", [this](const char *arg) {
         try {
            m_offload_threshold = str2num<decltype(m_offload_threshold)>(arg);
         } catch(std::invalid_argument &e) {
            return false;
         }
         return true;
      });
      register_option("rqs", "remove-queue-size", "size", "Maximal count of flows that are simultanously waiting for export packet from CTT. Default is 1024. At least 512.", [this](const char *arg) {
         try {
            m_ctt_remove_queue_size = str2num<decltype(m_ctt_remove_queue_size)>(arg);
         } catch(std::invalid_argument &e) {
            return false;
         }
         return m_ctt_remove_queue_size >= 512;
      });
   }
} // ipxp
