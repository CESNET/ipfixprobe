#ifndef NFBREADER_H
#define NFBREADER_H

#include <stdint.h>
#include <string>
#include <nfb/ndp.h>
#include "ndpheader.h"

class NdpReader
{
public:
    NdpReader(uint16_t packet_bufferSize = 50, uint64_t timeout = 300);
    ~NdpReader();

    int init_interface(const std::string &interface);
    void print_stats();
    void close();
    int get_pkt(struct ndp_packet **ndp_packet, struct ndp_header **ndp_header);
    std::string error_msg;
private:
	bool retrieve_ndp_packets();
    struct nfb_device *dev_handle; // NFB device
    struct ndp_queue *rx_handle; // data receiving NDP queue
	uint64_t processed_packets;
	uint16_t packet_bufferSize;
	uint64_t timeout;
	
	uint16_t ndp_packet_buffer_processed;
	uint16_t ndp_packet_buffer_packets;
	struct ndp_packet *ndp_packet_buffer;
	bool ndp_packet_buffer_valid;
};

#endif //NFBREADER_H
