/**
 * @file
 * @brief DPDK ring input interface for ipfixprobe (secondary DPDK app).
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Jaroslav Pesek <pesek@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <memory>
#include <sstream>

#include <ipfixprobe/inputPlugin.hpp>
#include <ipfixprobe/utils.hpp>
#include <rte_mbuf.h>
#include <rte_ring.h>

namespace ipxp {

class DpdkRingOptParser : public OptionsParser {
private:
	static constexpr size_t DEFAULT_MBUF_BURST_SIZE = 64;
	size_t pkt_buffer_size_;

	std::string ring_name_;
	std::string eal_;

public:
	DpdkRingOptParser()
		: OptionsParser(
			  "dpdk-ring",
			  "DPDK ring input interface for ipfixprobe (secondary DPDK app).")
		, pkt_buffer_size_(DEFAULT_MBUF_BURST_SIZE)
	{
		register_option(
			"b",
			"bsize",
			"SIZE",
			"Size of the MBUF packet buffer. Default: " + std::to_string(DEFAULT_MBUF_BURST_SIZE),
			[this](const char* arg) {
				try {
					pkt_buffer_size_ = str2num<decltype(pkt_buffer_size_)>(arg);
				} catch (std::invalid_argument&) {
					return false;
				}
				return true;
			},
			RequiredArgument);
		register_option(
			"r",
			"ring",
			"RING",
			"Name of the ring to read packets from. Need to be specified explicitly thus no "
			"default provided.",
			[this](const char* arg) {
				ring_name_ = arg;
				return true;
			},
			OptionFlags::RequiredArgument);
		register_option(
			"e",
			"eal",
			"EAL",
			"DPDK eal",
			[this](const char* arg) {
				eal_ = arg;
				return true;
			},
			OptionFlags::RequiredArgument);
	}
	size_t pkt_buffer_size() const { return pkt_buffer_size_; }

	std::string ring_name() const { return ring_name_; }

	std::string eal_params() const { return eal_; }
};

class DpdkRingCore {
public:
	/**
	 * @brief Configure DPDK secondary process.
	 *
	 * @param eal_params DPDK EAL parameters.
	 */
	void configure(const char* params);

	/**
	 * @brief Get the singleton dpdk core instance
	 */
	static DpdkRingCore& getInstance();
	void deinit();

	DpdkRingOptParser parser;

private:
	std::vector<char*> convertStringToArgvFormat(const std::string& ealParams);
	void configureEal(const std::string& ealParams);
	~DpdkRingCore();
	bool isConfigured = false;
	static DpdkRingCore* m_instance;
};

class DpdkRingReader : public InputPlugin {
public:
	Result get(PacketBlock& packets) override;

	void init(const char* params) override;

	OptionsParser* get_parser() const override { return new DpdkRingOptParser(); }

	std::string get_name() const override { return "dpdk-ring"; }

	~DpdkRingReader();
	DpdkRingReader(const std::string& params);

	void configure_telemetry_dirs(
		std::shared_ptr<telemetry::Directory> plugin_dir,
		std::shared_ptr<telemetry::Directory> queues_dir) override;

private:
	struct DpdkRingStats {
		uint64_t receivedPackets;
		uint64_t receivedBytes;
	};

	struct NfbMetadataDynfieldInfo {
		int dynflag_bit_index;
		int dynfield_byte_index;
	};

	struct NfbTimestamp {
		uint32_t timestamp_ns;
		uint32_t timestamp_s;
	} __rte_packed;

	struct NfbMetadata {
		NfbTimestamp timestamp;
		uint16_t matched;
		uint32_t hash;
	} __rte_packed;

	telemetry::Content get_queue_telemetry();
	void getDynfieldInfo();
	void prefetchPackets();

	std::vector<rte_mbuf*> mbufs_;
	std::uint16_t pkts_read_;

	void createRteMbufs(uint16_t mbufsSize);
	struct timeval getTimestamp(rte_mbuf* mbuf);
	DpdkRingCore& m_dpdkRingCore;
	rte_ring* m_ring;
	bool is_reader_ready = false;
	DpdkRingStats m_stats = {};
	bool m_nfbMetadataEnabled = false;
	NfbMetadataDynfieldInfo m_nfbMetadataDynfieldInfo = {};
};

} // namespace ipxp
