#pragma once

#include <cstddef>
#include <optional>
#include "flowRecord.hpp"

namespace ipxp {

class CacheRowSpan {
public:
   CacheRowSpan(FlowRecord** begin, size_t count) noexcept;
   std::optional<size_t> find_by_hash(uint64_t hash) const noexcept;
   void advance_flow(size_t flow_index) noexcept;
   void advance_flow_to(size_t from, size_t to) noexcept;
   std::optional<size_t> find_empty() const noexcept;
private:
   FlowRecord** m_begin;
   size_t m_count;
};

} // ipxp
