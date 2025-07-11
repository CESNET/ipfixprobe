#pragma once

#include "ndpHeader.hpp"

#include <span>
#include <string>
#include <vector>

#include <numa.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>

extern "C" {
#include <nfb/ndp.h>
#include <nfb/nfb.h>
}

namespace ipxp {

struct NdpReaderContext {
	void* reader;
};

extern void ndp_reader_init(struct NdpReaderContext* context);
extern void ndp_reader_free(struct NdpReaderContext* context);
extern const char* ndp_reader_error_msg(struct NdpReaderContext* context);
extern int ndp_reader_init_interface(struct NdpReaderContext* context, const char* interface);
extern void ndp_reader_print_stats(struct NdpReaderContext* context);
extern void ndp_reader_close(struct NdpReaderContext* context);
extern int ndp_reader_get_pkt(
	struct NdpReaderContext* context,
	struct ndp_packet** ndp_packet,
	struct ndp_header** ndp_header);

enum class NdpFwType {
	NDP_FW_HANIC,
	NDP_FW_NDK,
	NDP_FW_UNKNOWN,
};

class NdpReader {
public:
	NdpReader(uint16_t packet_bufferSize = 50, uint64_t timeout = 300);
	~NdpReader();

	int init_interface(const std::string& interface);
	void print_stats();
	void close();
	int get_pkt(struct ndp_packet** ndp_packet, struct timeval* timestamp);
	std::string error_msg;

	int get_packets(std::span<struct ndp_packet> packets, std::span<timeval> timestamps);

private:
	void set_booted_fw();
	void convert_fw_ts_to_timeval(const uint64_t* fw_ts, struct timeval* tv);
	void set_sw_timestamp(struct timeval* tv);
	bool retrieve_ndp_packets();
	struct nfb_device* dev_handle; // NFB device
	struct ndp_queue* rx_handle; // data receiving NDP queue
	uint64_t processed_packets;
	uint16_t packet_bufferSize;
	uint64_t timeout;

	uint64_t blocked_packets = 0;

	NdpFwType fw_type;
	std::vector<uint32_t> ndk_timestamp_offsets;

	uint16_t ndp_packet_buffer_processed;
	uint16_t ndp_packet_buffer_packets;
	struct ndp_packet* ndp_packet_buffer;
	bool ndp_packet_buffer_valid;
};

} // namespace ipxp
