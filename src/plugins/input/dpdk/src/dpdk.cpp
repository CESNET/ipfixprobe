/**
 * @file
 * @brief DPDK reader
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "dpdk.hpp"

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

#define MEMPOOL_CACHE_SIZE 256

namespace ipxp {

static const PluginManifest dpdkPluginManifest = {
	.name = "dpdk",
	.description = "Input plugin for reading packets using DPDK interface.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			DpdkOptParser parser;
			parser.usage(std::cout);
		},
};

DpdkCore* DpdkCore::m_instance = nullptr;

DpdkCore& DpdkCore::getInstance()
{
	if (!m_instance) {
		m_instance = new DpdkCore();
	}
	return *m_instance;
}

DpdkCore::~DpdkCore()
{
	m_dpdkDevices.clear();
	// rte_eal_cleanup(); // segfault?
	m_instance = nullptr;
}

void DpdkCore::deinit()
{
	if (m_instance) {
		delete m_instance;
		m_instance = nullptr;
	}
}

uint16_t DpdkCore::getMbufsCount() const noexcept
{
	return m_mBufsCount;
}

void DpdkCore::configure(const char* params)
{
	if (isConfigured) {
		return;
	}

	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	uint16_t mempoolSize = parser.pkt_mempool_size();
	uint16_t rxQueueCount = parser.rx_queues();
	m_mBufsCount = parser.pkt_buffer_size();
	uint16_t mtuSize = parser.mtu_size();

	configureEal(parser.eal_params());

	m_dpdkDevices.reserve(parser.port_numbers().size());
	for (auto portID : parser.port_numbers()) {
		m_dpdkDevices.emplace_back(portID, rxQueueCount, mempoolSize, m_mBufsCount, mtuSize);
	}

	isConfigured = true;
}

std::vector<char*> DpdkCore::convertStringToArgvFormat(const std::string& ealParams)
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

void DpdkCore::configureEal(const std::string& ealParams)
{
	std::vector<char*> args = convertStringToArgvFormat(ealParams);

	if (rte_eal_init(args.size(), args.data()) < 0) {
		rte_exit(EXIT_FAILURE, "Cannot initialize RTE_EAL: %s\n", rte_strerror(rte_errno));
	}
}

uint16_t DpdkCore::getRxQueueId() noexcept
{
	return m_currentRxId++;
}

DpdkReader::DpdkReader(const std::string& params)
	: m_dpdkCore(DpdkCore::getInstance())
{
	init(params.c_str());
}

DpdkReader::~DpdkReader()
{
	m_dpdkCore.deinit();
}

telemetry::Content DpdkReader::get_port_telemetry(uint16_t portNumber)
{
	struct rte_eth_stats stats = {};
	rte_eth_stats_get(portNumber, &stats);

	telemetry::Dict dict;
	dict["received_packets"] = stats.ipackets;
	dict["dropped_packets"] = stats.imissed;
	dict["received_bytes"] = stats.ibytes;
	dict["errors_packets"] = stats.ierrors;
	return dict;
}

telemetry::Content DpdkReader::get_queue_telemetry()
{
	telemetry::Dict dict;
	dict["received_packets"] = m_stats.receivedPackets;
	dict["received_bytes"] = m_stats.receivedBytes;
	return dict;
}

void DpdkReader::configure_telemetry_dirs(
	std::shared_ptr<telemetry::Directory> plugin_dir,
	std::shared_ptr<telemetry::Directory> queues_dir)
{
	auto ports_dir = plugin_dir->addDir("ports");
	for (size_t portID = 0; portID < m_dpdkDeviceCount; portID++) {
		auto port_dir = ports_dir->addDir(std::to_string(portID));
		telemetry::FileOps statsOps
			= {[this, portID]() { return get_port_telemetry(portID); }, nullptr};
		register_file(port_dir, "stats", statsOps);
		m_portsTelemetry.emplace_back(portID, port_dir);
	}

	telemetry::FileOps statsOps = {[this]() { return get_queue_telemetry(); }, nullptr};
	register_file(queues_dir, "input-stats", statsOps);

	m_dpdkTelemetry = std::make_unique<DpdkTelemetry>(plugin_dir);
}

void DpdkReader::init(const char* params)
{
	m_dpdkCore.configure(params);
	m_rxQueueId = m_dpdkCore.getRxQueueId();
	m_dpdkDeviceCount = m_dpdkCore.getDpdkDeviceCount();
	mBufs.resize(m_dpdkCore.getMbufsCount());
}

InputPlugin::Result DpdkReader::get(PacketBlock& packets)
{
	parser_opt_t opt {&packets, false, false, 0};

	packets.cnt = 0;

	DpdkDevice& dpdkDevice = m_dpdkCore.getDpdkDevice(m_dpdkDeviceIndex++ % m_dpdkDeviceCount);
	uint16_t receivedPackets = dpdkDevice.receive(mBufs, m_rxQueueId);
	if (!receivedPackets) {
		return Result::TIMEOUT;
	}

	for (auto packetID = 0; packetID < receivedPackets; packetID++) {
		parse_packet(
			&opt,
			m_parser_stats,
			dpdkDevice.getPacketTimestamp(mBufs[packetID]),
			rte_pktmbuf_mtod(mBufs[packetID], const std::uint8_t*),
			rte_pktmbuf_data_len(mBufs[packetID]),
			rte_pktmbuf_data_len(mBufs[packetID]));
	}

	m_seen += receivedPackets;
	m_parsed += receivedPackets;

	m_stats.receivedPackets += receivedPackets;
	m_stats.receivedBytes += packets.bytes;

	return packets.cnt ? Result::PARSED : Result::NOT_PARSED;
}

static const PluginRegistrar<DpdkReader, InputPluginFactory> dpdkRegistrar(dpdkPluginManifest);

} // namespace ipxp
