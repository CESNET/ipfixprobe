/**
 * \file cacheoptparser.hpp
 * \brief NHT Flow Cache options parser
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

#ifndef IPFIXPROBE_CACHE_CACHEOPTPARSER_H
#define IPFIXPROBE_CACHE_CACHEOPTPARSER_H
#include <cstdint>
#include <ipfixprobe/options.hpp>

#ifdef IPXP_FLOW_CACHE_SIZE
static const uint32_t DEFAULT_FLOW_CACHE_SIZE = IPXP_FLOW_CACHE_SIZE;
#else
static const uint32_t DEFAULT_FLOW_CACHE_SIZE = 17; // 131072 records total
#endif /* IPXP_FLOW_CACHE_SIZE */

#ifdef IPXP_FLOW_LINE_SIZE
static const uint32_t DEFAULT_FLOW_LINE_SIZE = IPXP_FLOW_LINE_SIZE;
#else
static const uint32_t DEFAULT_FLOW_LINE_SIZE = 4; // 16 records per line
#endif /* IPXP_FLOW_LINE_SIZE */

namespace ipxp {
class CacheOptParser : public OptionsParser {
public:
    CacheOptParser();

    uint32_t m_cache_size; ///< Count of records in cache.
    uint32_t m_line_size; ///< Count of records in one cache.
    uint32_t m_active; ///< Maximal allowed time in cache since first accepted packet.
    uint32_t m_inactive; ///< Maximal allowed time in cache since last accepted packet.
    bool m_split_biflow; ///< Split one flow to two depending it is source to destination or vice
                         ///< versa.
    double m_periodic_statistics_sleep_time; ///< Amount of time in which periodic statistics must
                                             ///< reset
    bool m_enable_fragmentation_cache; ///< If true, fragmentation cache will try to complete port
                                       ///< information for fragmented packet
    std::size_t m_frag_cache_size; ///< Count of records in fragmentation cache
    time_t m_frag_cache_timeout; ///< Maximal timeout for fragments
};
}; // namespace ipxp
#endif // IPFIXPROBE_CACHE_CACHEOPTPARSER_H
