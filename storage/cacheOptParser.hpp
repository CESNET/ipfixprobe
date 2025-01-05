/**
* \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief Contains the CacheOptParser class for parsing cache options.
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

#pragma once

#include <cstdint>
#include <ipfixprobe/options.hpp>
#include <config.h>

namespace ipxp {

class CacheOptParser : public OptionsParser
{
public:
   uint32_t m_cache_size;
   uint32_t m_line_size;
   uint32_t m_active;
   uint32_t m_inactive;
   bool m_split_biflow;
   bool m_enable_fragmentation_cache;
   std::size_t m_frag_cache_size;
   time_t m_frag_cache_timeout;

   CacheOptParser();
};


} // ipxp
