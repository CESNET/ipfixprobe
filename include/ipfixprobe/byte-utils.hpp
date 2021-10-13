/**
 * \file byte-utils.hpp
 * \brief Byte manipulation utilities
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
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

#ifndef IPXP_BYTE_UTILS_HPP
#define IPXP_BYTE_UTILS_HPP

#include <stdint.h>
#include <endian.h>

namespace ipxp {

/**
 * \brief Swaps byte order of 8 B value.
 * @param value Value to swap
 * @return Swapped value
 */
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t swap_uint64(uint64_t value)
{
   return value;
}
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t swap_uint64(uint64_t value)
{
   value = ((value << 8) & 0xFF00FF00FF00FF00ULL ) | ((value >> 8) & 0x00FF00FF00FF00FFULL );
   value = ((value << 16) & 0xFFFF0000FFFF0000ULL ) | ((value >> 16) & 0x0000FFFF0000FFFFULL );
   return (value << 32) | (value >> 32);
}
# else
#  error  "Please fix <endian.h>"
# endif

}
#endif /* IPXP_BYTE_UTILS_HPP */
