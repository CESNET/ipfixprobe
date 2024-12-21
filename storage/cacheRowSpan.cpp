#include <algorithm>
#include "cacheRowSpan.hpp"

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

} // ipxp