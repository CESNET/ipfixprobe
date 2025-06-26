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

namespace ipxp {

class CacheOptParser : public OptionsParser
{
public:
   uint32_t m_cache_size; /**< Count of flows that cache can keep simultaneously. Calculated as 2^m_cache_size */
   uint32_t m_line_size; /**< Count of flows that can be stored in one line of the cache. Calculated as 2^m_line_size */
   uint32_t m_active; /**< Time in seconds after which the flow is considered active timeouted */
   uint32_t m_inactive; /**< Time in seconds after which the flow is considered inactive timeouted */
   bool m_split_biflow; /**< If true, the cache will split bi-directional flows into two unidirectional flows. */
   bool m_enable_fragmentation_cache; /**< If true, the cache will store fragmented packets and reassemble them. */
   std::size_t m_frag_cache_size; /**< Size of the fragmentation cache, used to store fragmented packets. */
   time_t m_frag_cache_timeout; /**< Timeout for the fragmentation cache, after which the fragmented packets are removed. */

   ~CacheOptParser() override = default;
   CacheOptParser(const std::string &name, const std::string &description);
};


} // ipxp
