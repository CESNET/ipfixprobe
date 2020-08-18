/**
 * \file conversion.cpp
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2014-2018 CESNET
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
#include <limits>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

using namespace std;

/**
 * \brief Remove whitespaces from beginning and end of string.
 * \param [in,out] str String to be trimmed.
 */
void trim_str(string &str)
{
   str.erase(0, str.find_first_not_of(" \t\n\r"));
   str.erase(str.find_last_not_of(" \t\n\r") + 1);
}

/**
 * \brief Provides conversion from string to uint64_t.
 * \param [in] str String representation of value.
 * \param [out] dst Destination variable.
 * \return True on success, false otherwise.
 */
bool str_to_uint64(string str, uint64_t &dst)
{
   char *check;
   errno = 0;
   trim_str(str);
   unsigned long long value = strtoull(str.c_str(), &check, 0);
   if (errno == ERANGE || str[0] == '-' || str[0] == '\0' || *check ||
      value > numeric_limits<uint64_t>::max()) {
      return false;
   }

   dst = value;
   return true;
}

/**
 * \brief Provides conversion from string to uint32_t.
 * \param [in] str String representation of value.
 * \param [out] dst Destination variable.
 * \return True on success, false otherwise.
 */
bool str_to_uint32(string str, uint32_t &dst)
{
   char *check;
   errno = 0;
   trim_str(str);
   unsigned long long value = strtoull(str.c_str(), &check, 0);
   if (errno == ERANGE || str[0] == '-' || str[0] == '\0' || *check ||
      value > numeric_limits<uint32_t>::max()) {
      return false;
   }

   dst = value;
   return true;
}

/**
 * \brief Provides conversion from string to uint16_t.
 * \param [in] str String representation of value.
 * \param [out] dst Destination variable.
 * \return True on success, false otherwise.
 */
bool str_to_uint16(string str, uint16_t &dst)
{
   char *check;
   errno = 0;
   trim_str(str);
   unsigned long long value = strtoull(str.c_str(), &check, 0);
   if (errno == ERANGE || str[0] == '-' || str[0] == '\0' || *check ||
      value > numeric_limits<uint16_t>::max()) {
      return false;
   }

   dst = value;
   return true;
}

/**
 * \brief Provides conversion from string to uint8_t.
 * \param [in] str String representation of value.
 * \param [out] dst Destination variable.
 * \return True on success, false otherwise.
 */
bool str_to_uint8(string str, uint8_t &dst)
{
   char *check;
   errno = 0;
   trim_str(str);
   unsigned long long value = strtoull(str.c_str(), &check, 0);
   if (errno == ERANGE || str[0] == '-' || str[0] == '\0' || *check ||
      value > numeric_limits<uint8_t>::max()) {
      return false;
   }

   dst = value;
   return true;
}

/**
 * \brief Provides conversion from string to double.
 * \param [in] str String representation of value.
 * \param [out] dst Destination variable.
 * \return True on success, false otherwise.
 */
bool str_to_double(string str, double &dst)
{
   char *check;
   errno = 0;
   trim_str(str);
   double value = strtod(str.c_str(), &check);
   if (errno == ERANGE || *check || str[0] == '\0') {
      return false;
   }

   dst = value;
   return true;
}

