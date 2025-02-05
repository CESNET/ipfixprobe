#pragma once

#include <config.h>
#include <cstdint>

namespace ipxp {

struct FlowEndReasonStats {
   uint64_t active_timeout{0};
   uint64_t inactive_timeout{0};
   uint64_t end_of_flow{0};
   uint64_t collision{0};
   uint64_t forced{0};
};

struct FlowRecordStats {
   uint64_t packets_count_1{0};
   uint64_t packets_count_2_5{0};
   uint64_t packets_count_6_10{0};
   uint64_t packets_count_11_20{0};
   uint64_t packets_count_21_50{0};
   uint64_t packets_count_51_plus{0};
};

struct FlowCacheStats{
   uint64_t empty{0};
   uint64_t not_empty{0};
   uint64_t hits{0};
   uint64_t exported{0};
   uint64_t flushed{0};
   uint64_t lookups{0};
   uint64_t lookups2{0};
   uint64_t flows_in_cache{0};
   uint64_t total_exported{0};
};

#ifdef WITH_CTT

struct CttStats {
   uint64_t flows_offloaded{0};
   uint64_t flows_removed{0};
   uint64_t export_packets{0};
   uint64_t export_packets_for_missing_flow{0};
   uint64_t export_packets_parsing_failed{0};
   struct {
      uint64_t counter_overflow{0};
      uint64_t tcp_eof{0};
      uint64_t active_timeout{0};
      uint64_t by_request{0};
      uint64_t ctt_full{0};
      uint64_t reserved{0};
   } export_reasons;
};

#endif /* WITH_CTT */

} // namespace ipxp
