#include <cstdio>
#include <cstring>
#include <iostream>
#include <nfb/nfb.h>
#include <numa.h>
#include <unistd.h>

#include "ndpreader.h"
#include "ndpreader.hpp"

/**
 * \brief Constructor.
 */
NdpReader::NdpReader(uint16_t packetBufferSize, uint64_t timeout)
    : dev_handle(nullptr)
    , rx_handle(NULL)
    , processed_packets(0)
    , packet_bufferSize(packetBufferSize)
    , timeout(timeout)
{
    ndp_packet_buffer = new struct ndp_packet[packet_bufferSize];
    ndp_packet_buffer_processed = 0;
    ndp_packet_buffer_packets = 0;
    ndp_packet_buffer_valid = false;
}

/**
 * \brief Destructor.
 */
NdpReader::~NdpReader()
{
    this->close();
}

/**
 * \brief Initialize network interface for reading.
 * \param [in] interface Interface name.
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int NdpReader::init_interface(const std::string& interface)
{
    std::string p_interface = interface;
    int channel = 0;
    std::size_t del_found = interface.find_last_of(":");
    if (del_found != std::string::npos) {
        std::string channel_str = interface.substr(del_found + 1);
        p_interface = interface.substr(0, del_found);
        channel = std::stoi(channel_str);
    }
    // Open NFB
    std::cout << "Opening device: " << p_interface.c_str() << " Channel: " << channel << std::endl;
    dev_handle = nfb_open(p_interface.c_str()); // path to NFB device
    if (!dev_handle) {
        error_msg = std::string() + "unable to open NFB device '" + p_interface + "'";
        return 1;
    }

    struct bitmask* bits = nullptr;
    int node_id;
    rx_handle = ndp_open_rx_queue(dev_handle, channel);
    if (!rx_handle) {
        error_msg = std::string() + "error opening NDP queue of NFB device";
        return 1;
    }
    if (((node_id = ndp_queue_get_numa_node(rx_handle)) >= 0)
        && // OPTIONAL: bind thread to correct NUMA node
        ((bits = numa_allocate_nodemask()) != nullptr)) {
        (void) numa_bitmask_setbit(bits, node_id);
        numa_bind(bits);
        numa_free_nodemask(bits);
    } else {
        error_msg = std::string() + "warning - NUMA node binding failed\n";
        return 1;
    }
    if (ndp_queue_start(rx_handle)) { // start capturing data from NDP queue
        error_msg = std::string() + "error starting NDP queue on NFB device";
        return 1;
    }
    return 0;
}

/**
 * \brief Close opened file or interface.
 */
void NdpReader::close()
{
    if (rx_handle) {
        ndp_queue_stop(rx_handle);
        ndp_close_rx_queue(rx_handle);
        rx_handle = nullptr;
    }
    if (dev_handle) { // close NFB device
        nfb_close(dev_handle);
        dev_handle = nullptr;
    }
    if (ndp_packet_buffer) {
        delete[] ndp_packet_buffer;
        ndp_packet_buffer = nullptr;
    }
}

void NdpReader::print_stats()
{
    std::cout << "NFB Reader processed packets: " << processed_packets << std::endl;
}

bool NdpReader::retrieve_ndp_packets()
{
    int ret;
    if (ndp_packet_buffer_valid) {
        ndp_rx_burst_put(rx_handle);
        ndp_packet_buffer_valid = false;
    }
    ret = ndp_rx_burst_get(rx_handle, ndp_packet_buffer, packet_bufferSize);
    if (ret > 0) {
        ndp_packet_buffer_processed = 0;
        ndp_packet_buffer_packets = ret;
        ndp_packet_buffer_valid = true;
        return true;
    } else if (ret < 0) {
        std::cerr << "RX Burst error: " << ret << std::endl;
    }

    return false;
}

int NdpReader::get_pkt(struct ndp_packet** ndp_packet_out, struct ndp_header** ndp_header_out)
{
    if (ndp_packet_buffer_processed >= ndp_packet_buffer_packets) {
        if (!retrieve_ndp_packets()) {
            return 0;
        }
    }

    struct ndp_packet* ndp_packet = (ndp_packet_buffer + ndp_packet_buffer_processed);
    *ndp_packet_out = ndp_packet;
    *ndp_header_out = (struct ndp_header*) ndp_packet->header;

    processed_packets++;
    ndp_packet_buffer_processed++;

    return 1;
}

#ifdef __cplusplus
extern "C" {
#endif

void ndp_reader_init(struct NdpReaderContext* context)
{
    context->reader = new NdpReader();
}
void ndp_reader_free(struct NdpReaderContext* context)
{
    delete ((NdpReader*) context->reader);
}
int ndp_reader_init_interface(struct NdpReaderContext* context, const char* interface)
{
    return ((NdpReader*) context->reader)->init_interface(std::string(interface));
}
void ndp_reader_print_stats(struct NdpReaderContext* context)
{
    ((NdpReader*) context->reader)->print_stats();
}
void ndp_reader_close(struct NdpReaderContext* context)
{
    ((NdpReader*) context->reader)->close();
}
int ndp_reader_get_pkt(
    struct NdpReaderContext* context,
    struct ndp_packet** ndp_packet,
    struct ndp_header** ndp_header)
{
    return ((NdpReader*) context->reader)->get_pkt(ndp_packet, ndp_header);
}
const char* ndp_reader_error_msg(struct NdpReaderContext* context)
{
    return ((NdpReader*) context->reader)->error_msg.c_str();
}

#ifdef __cplusplus
}
#endif
