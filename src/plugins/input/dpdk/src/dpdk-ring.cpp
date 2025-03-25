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

#include "dpdk-ring.hpp"

#include "parser.hpp"

#include <cstring>
#include <mutex>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_version.h>
#include <unistd.h>

namespace ipxp {

static const PluginManifest dpdkRingPluginManifest = {
	.name = "dpdk-ring",
	.description = "Input plugin for reading packets using DPDK ring.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			DpdkRingOptParser parser;
			parser.usage(std::cout);
		},
};

DpdkRingCore* DpdkRingCore::m_instance = nullptr;

DpdkRingCore& DpdkRingCore::getInstance()
{
	if (!m_instance) {
		m_instance = new DpdkRingCore();
	}
	return *m_instance;
}

DpdkRingCore::~DpdkRingCore()
{
	rte_eal_cleanup();
	m_instance = nullptr;
}

void DpdkRingCore::deinit()
{
	if (m_instance) {
		delete m_instance;
		m_instance = nullptr;
	}
}

void DpdkRingCore::configure(const char* params)
{
	if (isConfigured) {
		return;
	}

	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	configureEal(parser.eal_params());
	isConfigured = true;
}

std::vector<char*> DpdkRingCore::convertStringToArgvFormat(const std::string& ealParams)
{
	// set first value as program name (argv[0])
	const char* programName = "ipfixprobe";
	char* programArg = new char[strlen(programName) + 1];
	strcpy(programArg, programName);
	std::vector<char*> args;
	args.push_back(programArg);
	std::istringstream iss(ealParams);
	std::string token;

	while (iss >> token) {
		char* arg = new char[token.size() + 1];
		copy(token.begin(), token.end(), arg);
		arg[token.size()] = '\0';
		args.push_back(arg);
	}
	return args;
}

void DpdkRingCore::configureEal(const std::string& ealParams)
{
	std::vector<char*> args = convertStringToArgvFormat(ealParams);

	if (rte_eal_init(args.size(), args.data()) < 0) {
		rte_exit(EXIT_FAILURE, "Cannot initialize RTE_EAL: %s\n", rte_strerror(rte_errno));
	}
}

DpdkRingReader::DpdkRingReader(const std::string& params)
	: m_dpdkRingCore(DpdkRingCore::getInstance())
{
	pkts_read_ = 0;
	init(params.c_str());
}

DpdkRingReader::~DpdkRingReader()
{
	m_dpdkRingCore.deinit();
}

void DpdkRingReader::createRteMbufs(uint16_t mbufsSize)
{
	try {
		mbufs_.resize(mbufsSize);
	} catch (const std::exception& e) {
		throw PluginError(e.what());
	}
}

void DpdkRingReader::init(const char* params)
{
	m_dpdkRingCore.configure(params);
	DpdkRingOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}
	createRteMbufs(m_dpdkRingCore.parser.pkt_buffer_size());
	m_ring = rte_ring_lookup(parser.ring_name().c_str());
	if (!m_ring) {
		throw PluginError("Cannot find ring with name: " + parser.ring_name());
	} else {
		is_reader_ready = true;
	}
	getDynfieldInfo();
}

struct timeval DpdkRingReader::getTimestamp(rte_mbuf* mbuf)
{
	struct timeval tv;
	if (m_nfbMetadataEnabled) {
		uint64_t nfb_dynflag_mask = (1ULL << m_nfbMetadataDynfieldInfo.dynflag_bit_index);

		if (mbuf->ol_flags & nfb_dynflag_mask) {
			const uint16_t ct_hdr_offset = *RTE_MBUF_DYNFIELD(
				mbuf,
				m_nfbMetadataDynfieldInfo.dynfield_byte_index,
				uint16_t*);

			struct NfbMetadata* ct_hdr
				= (struct NfbMetadata*) ((uint8_t*) mbuf->buf_addr + ct_hdr_offset);

			tv.tv_sec = ct_hdr->timestamp.timestamp_s;
			tv.tv_usec = ct_hdr->timestamp.timestamp_ns / 1000;
			return tv;
		}
	}

	// fallback to software timestamp
	auto now = std::chrono::system_clock::now();
	auto now_t = std::chrono::system_clock::to_time_t(now);

	auto dur = now - std::chrono::system_clock::from_time_t(now_t);
	auto micros = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();

	tv.tv_sec = now_t;
	tv.tv_usec = micros;
	return tv;
}

InputPlugin::Result DpdkRingReader::get(PacketBlock& packets)
{
	while (is_reader_ready == false) {
		usleep(1000);
	}

	parser_opt_t opt {&packets, false, false, 0};

	packets.cnt = 0;
	for (auto i = 0; i < pkts_read_; i++) {
		rte_pktmbuf_free(mbufs_[i]);
	}
	pkts_read_ = rte_ring_dequeue_burst(
		m_ring,
		reinterpret_cast<void**>(mbufs_.data()),
		mbufs_.capacity(),
		nullptr);
	if (pkts_read_ == 0) {
		return Result::TIMEOUT;
	}
	prefetchPackets();
	for (auto i = 0; i < pkts_read_; i++) {
		parse_packet(
			&opt,
			m_parser_stats,
			getTimestamp(mbufs_[i]),
			rte_pktmbuf_mtod(mbufs_[i], const std::uint8_t*),
			rte_pktmbuf_data_len(mbufs_[i]),
			rte_pktmbuf_data_len(mbufs_[i]));
		m_seen++;
		m_parsed++;
	}

	m_stats.receivedPackets += pkts_read_;
	m_stats.receivedBytes += packets.bytes;

	return opt.pblock->cnt ? Result::PARSED : Result::NOT_PARSED;
}

telemetry::Content DpdkRingReader::get_queue_telemetry()
{
	telemetry::Dict dict;
	dict["received_packets"] = m_stats.receivedPackets;
	dict["received_bytes"] = m_stats.receivedBytes;
	return dict;
}

void DpdkRingReader::configure_telemetry_dirs(
	std::shared_ptr<telemetry::Directory> plugin_dir,
	std::shared_ptr<telemetry::Directory> queues_dir)
{
	(void) plugin_dir;
	telemetry::FileOps statsOps = {[this]() { return get_queue_telemetry(); }, nullptr};
	register_file(queues_dir, "input-stats", statsOps);
}

void DpdkRingReader::getDynfieldInfo()
{
	struct rte_mbuf_dynfield dynfield_params;
	struct rte_mbuf_dynflag dynflag_param;
	int ret;
	bool dynflag_found = false;
	bool dynfield_found = false;

	rte_errno = 0;
	ret = rte_mbuf_dynflag_lookup("rte_net_nfb_dynflag_header_vld", &dynflag_param);
	if (ret >= 0) {
		m_nfbMetadataDynfieldInfo.dynflag_bit_index = ret;
		dynflag_found = true;
	}

	rte_errno = 0;
	ret = rte_mbuf_dynfield_lookup("rte_net_nfb_dynfield_header_offset", &dynfield_params);
	if (ret >= 0) {
		m_nfbMetadataDynfieldInfo.dynfield_byte_index = ret;
		dynfield_found = true;
	}

	if (dynflag_found && dynfield_found) {
		m_nfbMetadataEnabled = true;
	}
}

void DpdkRingReader::prefetchPackets()
{
	for (auto i = 0; i < pkts_read_; i++) {
		__builtin_prefetch(mbufs_[i], 0, 2);
		__builtin_prefetch((uint8_t*) mbufs_[i] + 64, 0, 2);
	}
}

static const PluginRegistrar<DpdkRingReader, InputPluginFactory>
	dpdkRingRegistrar(dpdkRingPluginManifest);

} // namespace ipxp
