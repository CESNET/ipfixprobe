#pragma once

#include <cstdint>

namespace ipxp {

struct FlowEndReasonStats {
   uint64_t active_timeout{0}; ///< Flows ended due to active timeout
   uint64_t inactive_timeout{0}; ///< Flows ended due to inactive timeout
   uint64_t end_of_flow{0}; ///< Flows ended due to end of flow (e.g., TCP FIN)
   uint64_t collision{0}; ///< Flows ended due to lack of space in the row 
   uint64_t forced{0}; ///< Flows ended due to process plugins
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
   uint64_t empty{0};  ///< Empty place found on flow creation
   uint64_t not_empty{0}; ///< Some victim was exported on flow creation
   uint64_t hits{0}; ///< Number of successful lookups
   uint64_t exported{0}; ///< Number of flows exported
   uint64_t flushed{0}; ///< Number of flows flushed by process plugins
   uint64_t lookups{0}; ///< Sum of all checked cells during all flows searches
   uint64_t lookups2{0}; ///< Sum of all checked cells squared during all flows searches
   uint64_t flows_in_cache{0}; ///< Number of flows currently in cache
};

struct CttStats {
   uint64_t total_requests_count{0};  ///< Total number of requests sent to CTT
   uint64_t lost_requests_count{0};  ///< Number of lost requests to CTT(no response during timeout)
   uint64_t real_processed_packets{0}; ///< Number of packets processed by CTT (counting offloaded packets)
   uint64_t flows_offloaded{0};  ///< Number of flows offloaded to CTT
   uint64_t trim_packet_offloaded{0};  ///< Number of flows offloaded to CTT with trim offload
   uint64_t drop_packet_offloaded{0};  ///< Number of flows offloaded to CTT with drop packet offload
   uint64_t flows_removed{0}; ///< Number of flows removed from CTT after export packet
   uint64_t export_packets{0}; ///< Number of export packets accepted from CTT(including pv0)
   uint64_t export_packets_for_missing_flow{0}; ///< Number of export packets for which no corresponding flow in ipfixprobe cache was found
   uint64_t export_packets_parsing_failed{0}; ///< Number of export packets that couldn't be parsed
   uint64_t remove_queue_lost_requests{0}; ///< Number of requests lost in CTT remove queue
   uint64_t flush_ctt_lost_requests{0}; ///< Number of requests lost on CTT flush 
   uint64_t wb_before_pv1[2]{0, 0}; ///< Count of writeback flags including invalid packets
   uint64_t wb_after_pv1[2]{0, 0};  ///< Count of writeback flags excluding invalid packets
   uint64_t pv_zero{0}; ///< Number of export packets with pv == 0
   
   /**
     * @brief Counters for all possible CTT export reasons
     */ 
   struct ExportReasons{
      uint64_t counter_overflow{0}; ///< Count of packets in the offloaded flow exceeded counter maximum 
      uint64_t tcp_eof{0};  ///< TCP connection end
      uint64_t active_timeout{0}; ///< Active timeout reached
      uint64_t by_request{0}; ///< Export by request from ipfixprobe
      uint64_t ctt_full{0}; ///< CTT hash collision
      uint64_t hash_collision{0}; ///< Another kind of CTT hash collision
      uint64_t reserved{0}; ///< Reserved for future use, must be 0 
   };
   ExportReasons export_reasons_before_pv1;  ///< Export reasons including pv0 packets
   ExportReasons export_reasons_after_pv1;   ///< Export reasons excluding pv0 packets

   struct {
      uint64_t counter_overflow[2]{0, 0};
      uint64_t tcp_eof[2]{0, 0};
      uint64_t active_timeout[2]{0, 0};
      uint64_t by_request[2]{0, 0};
      uint64_t ctt_full[2]{0, 0};
      uint64_t hash_collision[2]{0, 0};
      uint64_t reserved[2]{0, 0};
   } advanced_export_reasons;  ///< Export reasons of pv1 packets, split by writeback flag (0 or 1)
};

} // namespace ipxp
