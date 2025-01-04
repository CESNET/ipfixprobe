/**
* \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief CacheRowSpan implementation.
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

#include "cacheRowSpan.hpp"

#include <algorithm>

#include "fragmentationCache/timevalUtils.hpp"

namespace ipxp {

CacheRowSpan::CacheRowSpan(FlowRecord** begin, size_t count) noexcept
   : m_begin(begin), m_count(count)
{
}

std::optional<size_t> CacheRowSpan::find_by_hash(uint64_t hash) const noexcept
{
   for (size_t i = 0; i < m_count; ++i) {
      if (m_begin[i]->belongs(hash)) {
         return i;
      }
   }
   return std::nullopt;
}

void CacheRowSpan::advance_flow_to(size_t from, size_t to) noexcept
{
   if (from < to) {
      std::rotate(m_begin + from, m_begin + from + 1, m_begin + to + 1);
      return;
   }
   std::rotate(m_begin + to, m_begin + from, m_begin + from + 1);
}

void CacheRowSpan::advance_flow(size_t flow_index) noexcept
{
   advance_flow_to(flow_index, 0);
}

std::optional<size_t> CacheRowSpan::find_empty() const noexcept
{
   auto it = std::find_if(m_begin, m_begin + m_count, [](const FlowRecord* flow) {
      return flow->is_empty();
   });
   if (it == m_begin + m_count) {
      return std::nullopt;
   }
   return it - m_begin;
}

#ifdef WITH_CTT
std::optional<size_t> CacheRowSpan::find_if_export_timeout_expired(const timeval& now) const noexcept
{
   auto it = std::find_if(m_begin, m_begin + m_count, [&now](const FlowRecord* flow) {
      return flow->is_waiting_for_export && now > flow->export_time;
   });
   if (it == m_begin + m_count) {
      return std::nullopt;
   }
   return it - m_begin;
}

size_t CacheRowSpan::find_victim(const timeval& now) const noexcept
{
   const FlowRecord** victim = const_cast<const FlowRecord**>(m_begin) + m_count - 1;
   auto it = std::find_if(m_begin, m_begin + m_count, [&](const FlowRecord* flow) {
      if (!flow->is_in_ctt) {
         victim = &flow;
      }
      return flow->is_waiting_for_export && now > flow->export_time;
   });
   if (it == m_begin + m_count) {
      return victim - const_cast<const FlowRecord**>(m_begin);
   }
   return it - m_begin;
}

#endif /* WITH_CTT */

} // ipxp