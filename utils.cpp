/**
 * \file utils.cpp
 * \brief Utility functions source
 * \author Jiri Havranek <havranek@cesnet.cz>
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
 *
 */

#include <string>
#include <utility>

#include <ipfixprobe/utils.hpp>

namespace ipxp {

void parse_range(const std::string &arg, std::string &from, std::string &to, const std::string &delim)
{
   size_t pos = arg.find(delim);
   if (pos == std::string::npos) {
      throw std::invalid_argument(arg);
   }

   if (delim.find("-") != std::string::npos) {
      size_t tmp = arg.find_first_not_of(" \t\r\n");
      if (arg[tmp] == '-') {
         tmp = arg.find(delim, pos + 1);
         if (tmp != std::string::npos) {
            pos = tmp;
         }
      }
   }

   from = arg.substr(0, pos);
   to = arg.substr(pos + 1);
   trim_str(from);
   trim_str(to);
}

bool str2bool(std::string str)
{
   std::set<std::string> accepted_values = {"y", "yes", "t", "true", "on", "1"};
   trim_str(str);
   std::transform(str.begin(), str.end(), str.begin(), ::tolower);
   return accepted_values.find(str) != accepted_values.end();
}

void trim_str(std::string &str)
{
   str.erase(0, str.find_first_not_of(" \t\n\r"));
   str.erase(str.find_last_not_of(" \t\n\r") + 1);
}

void phton64(uint8_t *p, uint64_t v)
{
   int shift = 56;

   for (unsigned int i = 0; i < 8; i++) {
      p[i] = (uint8_t) (v >> (shift - (i * 8)));
   }
}

uint64_t pntoh64(const void *p)
{
   uint64_t buffer = 0;
   int shift       = 56;

   for (unsigned x = 0; x < 8; x++) {
      buffer |= (uint64_t) *((const uint8_t *) (p) + x) << (shift - (x * 8));
   }
   return buffer;
}

}
