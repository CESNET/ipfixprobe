#ifndef NFBREADER_HPP
#define NFBREADER_HPP

#include "ndpheader.h"

#include <stdint.h>
#include <string>
#include <vector>
#include <nfb/ndp.h>
#include <sys/time.h>

enum class NdpFwType {
   NDP_FW_HANIC,
   NDP_FW_NDK,
   NDP_FW_UNKNOWN,
};

class NdpReader
{
public:
   NdpReader(uint16_t packet_bufferSize = 50, uint64_t timeout = 300);
   ~NdpReader();

   int init_interface(const std::string &interface);
   void print_stats();
   void close();
   int get_pkt(struct ndp_packet **ndp_packet, struct timeval *timestamp);
   std::string error_msg;
private:
   void set_booted_fw();
   void convert_fw_ts_to_timeval(const uint64_t *fw_ts, struct timeval *tv);
   void set_sw_timestamp(struct timeval *tv);
   bool retrieve_ndp_packets();
   struct nfb_device *dev_handle; // NFB device
   struct ndp_queue *rx_handle; // data receiving NDP queue
   uint64_t processed_packets;
   uint16_t packet_bufferSize;
   uint64_t timeout;

   NdpFwType fw_type;
   std::vector<uint32_t> ndk_timestamp_offsets;

   uint16_t ndp_packet_buffer_processed;
   uint16_t ndp_packet_buffer_packets;
   struct ndp_packet *ndp_packet_buffer;
   bool ndp_packet_buffer_valid;
};

#endif //NFBREADER_HPP
