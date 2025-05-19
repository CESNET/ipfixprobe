#include "ndpReader.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>

namespace ipxp {

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

	set_booted_fw();
	if (fw_type == NdpFwType::NDP_FW_UNKNOWN) {
		error_msg = std::string() + "unknown NDP firmware type";
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

void NdpReader::set_booted_fw()
{
	const void* fdt = nfb_get_fdt(dev_handle);
	const void* prop;
	int len;

	int fdt_offset = fdt_path_offset(fdt, "/firmware/");
	if (fdt_offset < 0) {
		fw_type = NdpFwType::NDP_FW_UNKNOWN;
		return;
	}
	prop = fdt_getprop(fdt, fdt_offset, "project-name", &len);
	if (!prop) {
		fw_type = NdpFwType::NDP_FW_UNKNOWN;
		return;
	}

	std::string name = (const char*) prop;
	if (name.find("NDK_") != std::string::npos) {
		fw_type = NdpFwType::NDP_FW_NDK;
		int header_id = 0;
		do {
			int direction = 0;
			fdt_offset = ndp_header_fdt_node_offset(fdt, direction, header_id);
			if (fdt_offset < 0) {
				break;
			}

			struct nfb_fdt_packed_item packet_item
				= nfb_fdt_packed_item_by_name(fdt, fdt_offset, "timestamp");
			if (packet_item.name == nullptr) {
				ndk_timestamp_offsets.emplace_back(-1);
				header_id++;
				continue;
			}

			int offset = packet_item.offset / 8; // bits to bytes
			ndk_timestamp_offsets.emplace_back(offset);
			header_id++;
		} while (true);

	} else if (name.find("HANIC_") != std::string::npos) {
		fw_type = NdpFwType::NDP_FW_HANIC;
	} else {
		fw_type = NdpFwType::NDP_FW_UNKNOWN;
	}
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

void NdpReader::convert_fw_ts_to_timeval(const uint64_t* ts, struct timeval* tv)
{
	uint32_t sec = (*ts) >> 32;
	uint32_t nsec = (*ts) & 0xFFFFFFFF;

	tv->tv_sec = le32toh(sec);
	tv->tv_usec = le32toh(nsec) / 1000;
}

void NdpReader::set_sw_timestamp(struct timeval* tv)
{
	auto now = std::chrono::system_clock::now();
	auto now_t = std::chrono::system_clock::to_time_t(now);

	auto dur = now - std::chrono::system_clock::from_time_t(now_t);
	auto micros = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();

	tv->tv_sec = now_t;
	tv->tv_usec = micros;
}

int NdpReader::get_packets(std::span<struct ndp_packet> packets, std::span<timeval> timestamps)
{
	if (blocked_packets > 128) {
		ndp_rx_burst_put(rx_handle);
		blocked_packets = 0;
	}

	const unsigned received = ndp_rx_burst_get(rx_handle, packets.data(), packets.size());
	for (unsigned i = 0; i < received; i++) {
		struct ndp_packet* ndp_packet = &packets[i];
		if (fw_type == NdpFwType::NDP_FW_HANIC) {
			uint64_t* fw_ts = &((NdpHeader*) (ndp_packet->header))->timestamp;
			if (*fw_ts == 0) {
				set_sw_timestamp((struct timeval*) &timestamps[i]);
			} else {
				convert_fw_ts_to_timeval(fw_ts, (struct timeval*) &timestamps[i]);
			}
		} else {
			uint8_t header_id = ndp_packet_flag_header_id_get(ndp_packet);
			if (header_id >= ndk_timestamp_offsets.size()) {
				set_sw_timestamp((struct timeval*) &timestamps[i]);
			} else if (ndk_timestamp_offsets[header_id] == std::numeric_limits<uint32_t>::max()) {
				set_sw_timestamp((struct timeval*) &timestamps[i]);
			} else {
				uint64_t* fw_ts = (uint64_t*) ((uint8_t*) ndp_packet->header
											   + ndk_timestamp_offsets[header_id]);
				if (*fw_ts == std::numeric_limits<uint64_t>::max()) {
					set_sw_timestamp((struct timeval*) &timestamps[i]);
				} else {
					convert_fw_ts_to_timeval(fw_ts, (struct timeval*) &timestamps[i]);
				}
			}
		}
	}

	blocked_packets += received;

	return received;
}

int NdpReader::get_pkt(struct ndp_packet** ndp_packet_out, struct timeval* timestamp)
{
	if (ndp_packet_buffer_processed >= ndp_packet_buffer_packets) {
		if (!retrieve_ndp_packets()) {
			return 0;
		}
	}

	struct ndp_packet* ndp_packet = (ndp_packet_buffer + ndp_packet_buffer_processed);
	*ndp_packet_out = ndp_packet;
	if (fw_type == NdpFwType::NDP_FW_HANIC) {
		uint64_t* fw_ts = &((NdpHeader*) (ndp_packet->header))->timestamp;
		if (*fw_ts == 0) {
			set_sw_timestamp(timestamp);
		} else {
			convert_fw_ts_to_timeval(fw_ts, timestamp);
		}
	} else {
		uint8_t header_id = ndp_packet_flag_header_id_get(ndp_packet);
		if (header_id >= ndk_timestamp_offsets.size()) {
			set_sw_timestamp(timestamp);
		} else if (ndk_timestamp_offsets[header_id] == std::numeric_limits<uint32_t>::max()) {
			set_sw_timestamp(timestamp);
		} else {
			uint64_t* fw_ts
				= (uint64_t*) ((uint8_t*) ndp_packet->header + ndk_timestamp_offsets[header_id]);
			if (*fw_ts == std::numeric_limits<uint64_t>::max()) {
				set_sw_timestamp(timestamp);
			} else {
				convert_fw_ts_to_timeval(fw_ts, timestamp);
			}
		}
	}

	processed_packets++;
	ndp_packet_buffer_processed++;

	return 1;
}

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

const char* ndp_reader_error_msg(struct NdpReaderContext* context)
{
	return ((NdpReader*) context->reader)->error_msg.c_str();
}

} // namespace ipxp
