/**
 * \file cachestatistics.hpp
 * \brief Statistics about packet insertion into cache
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

#ifndef IPFIXPROBE_CACHE_CACHESTATISTICS_HPP
#define IPFIXPROBE_CACHE_CACHESTATISTICS_HPP

#include <cstdint>
#include <ostream>
namespace ipxp {
struct CacheStatistics {
    CacheStatistics();
    uint32_t m_empty;
    uint32_t m_not_empty;
    uint32_t m_hits;
    uint32_t m_expired;
    uint32_t m_flushed;
    uint32_t m_lookups;
    uint32_t m_lookups2;
    uint32_t m_put_time;
    CacheStatistics operator-(const CacheStatistics& o) const noexcept;
    friend std::ostream& operator<<(std::ostream& os, const CacheStatistics& statistics) noexcept;
};
} // namespace ipxp

#endif // IPFIXPROBE_CACHE_CACHESTATISTICS_HPP
