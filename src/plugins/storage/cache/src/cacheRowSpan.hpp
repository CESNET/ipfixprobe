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

#pragma once

#include <cstddef>
#include <optional>
#include <cstring>

#include "flowRecord.hpp"
#include "fragmentationCache/timevalUtils.hpp"
#include "flowKey.hpp"

namespace ipxp {
/**
 * \brief Class representing a non-owning view of a row span in a cache.
 */
class CacheRowSpan {
public:
   /**
    * \brief Construct a new CacheRowSpan object.
    * \param begin Pointer to the first element in the row.
    * \param count Number of elements in the row.
    */
   CacheRowSpan(FlowRecord** begin, size_t count) noexcept
   : m_begin(begin), m_count(count)
   {
   }

   /**
    * \brief Find a flow record by hash.
    * \param hash Hash value to search for.
    * \return Index of the flow record relative to row begin if found, std::nullopt otherwise.
    */
   __attribute__((always_inline)) std::optional<size_t> find_by_hash(uint64_t hash) const noexcept
   {
      for (size_t i = 0; i < m_count; ++i) {
         if (m_begin[i]->belongs(hash)) {
             return i;
         }
      }
     return std::nullopt;
   }

   /**
    * \brief Move a flow record to the beginning of the row.
    * \param flow_index Index of the flow record to move.
    */
   __attribute__((always_inline)) void advance_flow(size_t flow_index) noexcept
   {
      advance_flow_to(flow_index, 0);
   }

   /**
    * \brief Move a flow record to a specific position in the row.
    * \param from Index of the flow record to move.
    * \param to Index of the position to move the flow record to.
    */
   __attribute__((always_inline)) void advance_flow_to(size_t from, size_t to) noexcept
   {
      if (from == to) return;

      FlowRecord* tmp = m_begin[from];

      if (from < to) {
         std::memmove(m_begin + from, m_begin + from + 1, (to - from) * sizeof(FlowRecord*));
         m_begin[to] = tmp;
      } else {
         std::memmove(m_begin + to + 1, m_begin + to, (from - to) * sizeof(FlowRecord*));
         m_begin[to] = tmp;
      }
      return;
   }

   /**
    * \brief Find an empty flow record in the row.
    * \return Index of the empty flow record if found, std::nullopt otherwise.
    */
   __attribute__((always_inline)) std::optional<size_t> find_empty() const noexcept
   {
      for (size_t i = 0; i < m_count; ++i) {
         if (m_begin[i]->is_empty()) {
               return i;
         }
      }
      return std::nullopt;
   }

   /**
    * \brief Access a flow record by index
    * \param index Index of the flow record to access.
    * \return Reference to the flow record at the specified index.
    */
   __attribute__((always_inline)) FlowRecord*& operator[](const size_t index) const noexcept
   {
      return m_begin[index];
   }

private:
   FlowRecord** m_begin;
   size_t m_count;
};

} // ipxp
