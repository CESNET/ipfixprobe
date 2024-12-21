#pragma once

#include <cstdint>
#include <ipfixprobe/options.hpp>






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
   #ifdef WITH_CTT
   std::string m_dev;
   #endif /* WITH_CTT */

   CacheOptParser();
};


} // ipxp
