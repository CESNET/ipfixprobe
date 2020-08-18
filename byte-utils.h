/**
 * \file ipfixexporter.cpp
 * \brief Export flows in IPFIX format.
 *    The following code was used https://dior.ics.muni.cz/~velan/flowmon-export-ipfix/
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2012 Masaryk University, Institute of Computer Science
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 * 3. Neither the name of the Masaryk University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
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
*/
#include <stdint.h>

/**
 * \brief Swaps byte order of 8 B value.
 * @param value Value to swap
 * @return Swapped value
 */
#if BYTEORDER == 4321 /* Big endian */
static inline uint64_t swap_uint64(uint64_t value)
{
   return value;
}
#else
static inline uint64_t swap_uint64(uint64_t value)
{
   value = ((value << 8) & 0xFF00FF00FF00FF00ULL ) | ((value >> 8) & 0x00FF00FF00FF00FFULL );
   value = ((value << 16) & 0xFFFF0000FFFF0000ULL ) | ((value >> 16) & 0x0000FFFF0000FFFFULL );
   return (value << 32) | (value >> 32);
}
#endif
