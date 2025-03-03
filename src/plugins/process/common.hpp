/**
 * \file common.hpp
 * \brief Common function for processing modules
 * \author Pavel Siska <siska@cesnet.cz>
 * \date 2022
 */
/*
 * Copyright (C) 2022 CESNET
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
 *
 *
 */

#ifndef IPXP_PROCESS_COMMON_HPP
#define IPXP_PROCESS_COMMON_HPP

#include <cstring>

namespace ipxp {

static inline bool check_payload_len(size_t payload_len, size_t required_len) noexcept
{
   return payload_len < required_len;
}

/**
 * \brief Returns a pointer to the first occurrence of str2 in str1,
 *        or a null pointer if str2 is not part of str1.
 *
 * \param str1 C string to be scanned.
 * \param str2 C string containing the sequence of characters to match.
 * \param len Number of bytes to be analyzed.
 * 
 * \return A pointer to the first occurrence of string in str1.
 *         If the string is not found, the function returns a null pointer.
 */
static inline const char *
strnstr(const char *str1, const char *str2, size_t len) noexcept
{
   char c, sc;
   size_t slen;

   if ((c = *str2++) != '\0') {
      slen = strlen(str2);
      do {
         do {
            if (len-- < 1 || (sc = *str1++) == '\0')
               return (NULL);
         } while (sc != c);
         if (slen > len)
            return (NULL);
      } while (strncmp(str1, str2, slen) != 0);
      str1--;
   }
   return ((char *)str1);
}

}

#endif /* IPXP_PROCESS_COMMON_HPP */
