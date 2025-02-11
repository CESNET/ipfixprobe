/**
* \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief CacheRowSpan declaration.
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
#include "flowRecord.hpp"

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
   CacheRowSpan(FlowRecord** begin, size_t count) noexcept;

   /**
    * \brief Find a flow record by hash.
    * \param hash Hash value to search for.
    * \return Index of the flow record relative to row begin if found, std::nullopt otherwise.
    */
   std::optional<size_t> find_by_hash(uint64_t hash, std::optional<uint16_t> vlan_id = std::nullopt) const noexcept;
   /**
    * \brief Move a flow record to the beginning of the row.
    * \param flow_index Index of the flow record to move.
    */
   void advance_flow(size_t flow_index) noexcept;

   /**
    * \brief Move a flow record to a specific position in the row.
    * \param from Index of the flow record to move.
    * \param to Index of the position to move the flow record to.
    */
   void advance_flow_to(size_t from, size_t to) noexcept;

   /**
    * \brief Find an empty flow record in the row.
    * \return Index of the empty flow record if found, std::nullopt otherwise.
    */
   std::optional<size_t> find_empty() const noexcept;

   __attribute__((always_inline)) FlowRecord*& operator[](const size_t index) const noexcept
   {
      return m_begin[index];
   }

#ifdef WITH_CTT
   /**
    * \brief Find a flow record to be evicted.
    * \param now Current time.
    * \return Index of flow from ctt which has delayed export timeout expired if found,
    * last record which is not in ctt, or last record otherwise
    */
   size_t find_victim(const timeval& now) const noexcept;
#endif /* WITH_CTT */
private:
   FlowRecord** m_begin;
   size_t m_count;
};

} // ipxp
