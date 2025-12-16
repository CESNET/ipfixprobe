/**
 * \file
 * \brief Implementation of the DpdkDevice class.
 * \author Pavel Siska <siska@cesnet.cz>
 * \date 2023
 */
/*
 * Copyright (C) 2023 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 */

#include "dpdkDevice.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>

#include <ipfixprobe/inputPlugin.hpp>
#include <rte_errno.h>
#include <rte_version.h>
#include <unistd.h>

namespace ipxp {

DpdkDevice::DpdkDevice(
	uint16_t portID,
	uint16_t rxQueueCount,
	uint16_t memPoolSize,
	uint16_t mbufsCount,
	uint16_t mtuSize)
	: m_portID(portID)
	, m_rxQueueCount(rxQueueCount)
	, m_txQueueCount(0)
	, m_mBufsCount(mbufsCount)
	, m_isNfbDpdkDriver(false)
	, m_supportedRSS(false)
	, m_supportedHWTimestamp(false)
	, m_mtuSize(mtuSize)
{
	validatePort();
	recognizeDriver();
	configurePort();
	initMemPools(memPoolSize);
	setupRxQueues(memPoolSize);
	enablePort();
}

DpdkDevice::~DpdkDevice()
{
	rte_eth_dev_stop(m_portID);
	rte_eth_dev_close(m_portID);
}

void DpdkDevice::validatePort()
{
	if (!rte_eth_dev_is_valid_port(m_portID)) {
		throw PluginError(
			"DpdkDevice::validatePort() has failed. Invalid DPDK port [" + std::to_string(m_portID)
			+ "] specified");
	}
}

void DpdkDevice::recognizeDriver()
{
	rte_eth_dev_info rteDevInfo;
	if (rte_eth_dev_info_get(m_portID, &rteDevInfo)) {
		throw PluginError("DpdkDevice::recognizeDriver() has failed. Unable to get rte dev info");
	}

	if (std::strcmp(rteDevInfo.driver_name, "net_nfb") == 0) {
		m_isNfbDpdkDriver = true;
		registerRxTimestamp();
		setRxTimestampDynflag();
	}

	std::cerr << "Capabilities of the port " << m_portID << " with driver "
			  << rteDevInfo.driver_name << ":" << std::endl;
	std::cerr << "\tRX offload: " << rteDevInfo.rx_offload_capa << std::endl;
	std::cerr << "\tflow type RSS offloads: " << rteDevInfo.flow_type_rss_offloads << std::endl;

	/* Check if RSS hashing is supported in NIC */
	m_supportedRSS = (rteDevInfo.flow_type_rss_offloads & RTE_ETH_RSS_IP) != 0;
	std::cerr << "\tDetected RSS offload capability: " << (m_supportedRSS ? "yes" : "no")
			  << std::endl;

	/* Check if HW timestamps are supported, we support NFB cards only */
	if (m_isNfbDpdkDriver) {
		m_supportedHWTimestamp = (rteDevInfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP) != 0;
	} else {
		m_supportedHWTimestamp = false;
	}
	std::cerr << "\tDetected HW timestamp capability: " << (m_supportedHWTimestamp ? "yes" : "no")
			  << std::endl;
}

void DpdkDevice::registerRxTimestamp()
{
	if (rte_mbuf_dyn_rx_timestamp_register(&m_rxTimestampOffset, NULL)) {
		throw PluginError(
			"DpdkDevice::registerRxTimestamp() has failed. Unable to get Rx timestamp offset");
	}
}

void DpdkDevice::setRxTimestampDynflag()
{
	m_rxTimestampDynflag
		= RTE_BIT64(rte_mbuf_dynflag_lookup(RTE_MBUF_DYNFLAG_RX_TIMESTAMP_NAME, NULL));
}

void DpdkDevice::configurePort()
{
	auto portConfig = createPortConfig();
	if (rte_eth_dev_configure(m_portID, m_rxQueueCount, m_txQueueCount, &portConfig)) {
		throw PluginError("DpdkDevice::configurePort() has failed. Unable to configure interface");
	}
	if (rte_eth_dev_set_mtu(m_portID, m_mtuSize)) {
		throw PluginError(
			"DpdkDevice::configurePort() has failed. Unable to set MTU (rte_eth_dev_set_mtu)");
	}
}

rte_eth_conf DpdkDevice::createPortConfig()
{
	if (m_rxQueueCount > 1 && !m_supportedRSS) {
		std::cerr << "RSS is not supported by card, multiple queues will not work as expected."
				  << std::endl;
		throw PluginError(
			"DpdkDevice::createPortConfig() has failed. Required RSS for q>1 is not supported.");
	}

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
	rte_eth_conf portConfig = {};
	portConfig.rxmode.mtu = m_mtuSize;
#else
	rte_eth_conf portConfig = {};
	portConfig.rxmode.max_rx_pkt_len = m_mtuSize;
#endif

	if (m_supportedRSS) {
		portConfig.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
		portConfig.rx_adv_conf.rss_conf = createRSSConfig();
	} else {
		std::cerr << "Skipped RSS hash setting for port " << m_portID << "." << std::endl;
		portConfig.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
	}

	if (m_supportedHWTimestamp) {
		portConfig.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
	}
	return portConfig;
}

void DpdkDevice::initMemPools(uint16_t memPoolSize)
{
	constexpr int MEMPOOL_CACHE_SIZE = 256;
	constexpr int VLAN_HDR_LEN = 4;
	constexpr int DPDK_MBUF_ALIGN = 1024;
	const int max_packet_size
		= RTE_ALIGN_CEIL(m_mtuSize + RTE_ETHER_HDR_LEN + VLAN_HDR_LEN, DPDK_MBUF_ALIGN);

	m_memPools.reserve(m_rxQueueCount);

	for (uint16_t rxQueueID = 0; rxQueueID < m_rxQueueCount; rxQueueID++) {
		std::string memPoolName
			= "mbuf_pool_" + std::to_string(m_portID) + "_" + std::to_string(rxQueueID);
		rte_mempool* memPool = rte_pktmbuf_pool_create(
			memPoolName.c_str(),
			memPoolSize,
			MEMPOOL_CACHE_SIZE,
			0,
			std::max(max_packet_size, RTE_MBUF_DEFAULT_DATAROOM) + RTE_PKTMBUF_HEADROOM,
			rte_eth_dev_socket_id(m_portID));
		if (!memPool) {
			throw PluginError(
				"DpdkDevice::initMemPool() has failed. Failed to create packets memory pool for "
				"port "
				+ std::to_string(m_portID) + ", pool name: " + memPoolName + ". Error was: '"
				+ std::string(rte_strerror(rte_errno))
				+ "' [Error code: " + std::to_string(rte_errno) + "]");
		}

		m_memPools.emplace_back(memPool);
	}
}

void DpdkDevice::setupRxQueues(uint16_t memPoolSize)
{
	const uint16_t rxQueueSize = std::max(memPoolSize / 2, 1);

	for (uint16_t rxQueueID = 0; rxQueueID < m_rxQueueCount; rxQueueID++) {
		int ret = rte_eth_rx_queue_setup(
			m_portID,
			rxQueueID,
			rxQueueSize,
			rte_eth_dev_socket_id(m_portID),
			nullptr,
			m_memPools[rxQueueID]);
		if (ret < 0) {
			throw PluginError(
				"DpdkDevice::setupRxQueues() has failed. Failed to set up RX queue(s) for port "
				+ std::to_string(m_portID));
		}
	}

	std::cerr << "DPDK RX queues for port " << m_portID
			  << " set up. Size of each queue: " << rxQueueSize << std::endl;
}

rte_eth_rss_conf DpdkDevice::createRSSConfig()
{
	struct rte_eth_rss_conf rssConfig = {};

	rte_eth_dev_info rteDevInfo;
	if (rte_eth_dev_info_get(m_portID, &rteDevInfo)) {
		throw PluginError("DpdkDevice::configureRSS() has failed. Unable to get rte dev info");
	}

	const uint8_t rssHashKeySize = rteDevInfo.hash_key_size;

	m_hashKey.resize(rssHashKeySize);
	std::generate(
		m_hashKey.begin(),
		m_hashKey.end(),
		[idx = static_cast<std::size_t>(0)]() mutable {
			static const std::array<uint8_t, 2> hashKey = {0x6D, 0x5A};
			return hashKey[idx++ % sizeof(hashKey)];
		});

	const uint64_t rssOffloads = rteDevInfo.flow_type_rss_offloads & RTE_ETH_RSS_IP;
	if (rssOffloads != RTE_ETH_RSS_IP) {
		std::cerr << "RTE_ETH_RSS_IP is not supported by the card. Used subset: " << rssOffloads
				  << std::endl;
	}

	rssConfig.rss_key = m_hashKey.data();
	rssConfig.rss_key_len = rssHashKeySize;
	rssConfig.rss_hf = rssOffloads;
	return rssConfig;
}

void DpdkDevice::enablePort()
{
	if (rte_eth_dev_start(m_portID) < 0) {
		throw PluginError("DpdkDevice::enablePort() has failed. Failed to start DPDK port");
	}

	if (rte_eth_promiscuous_enable(m_portID)) {
		throw PluginError("DpdkDevice::enablePort() has failed. Failed to set promiscuous mode");
	}

	std::cerr << "DPDK input at port " << m_portID << " started." << std::endl;
}

uint16_t DpdkDevice::receive(DpdkMbuf& dpdkMuf, uint16_t rxQueueID)
{
	dpdkMuf.releaseMbufs();
	uint16_t receivedPackets
		= rte_eth_rx_burst(m_portID, rxQueueID, dpdkMuf.data(), dpdkMuf.maxSize());
	dpdkMuf.setMbufsInUse(receivedPackets);
	return receivedPackets;
}

timeval DpdkDevice::getPacketTimestamp(rte_mbuf* mbuf)
{
	timeval tv;
	if (m_isNfbDpdkDriver && (mbuf->ol_flags & m_rxTimestampDynflag)) {
		static constexpr time_t nanosecInSec = 1000000000;
		static constexpr time_t nsecInUsec = 1000;

		rte_mbuf_timestamp_t timestamp
			= *RTE_MBUF_DYNFIELD(mbuf, m_rxTimestampOffset, rte_mbuf_timestamp_t*);
		tv.tv_sec = timestamp / nanosecInSec;
		tv.tv_usec = (timestamp - ((tv.tv_sec) * nanosecInSec)) / nsecInUsec;

		return tv;
	} else {
		auto now = std::chrono::system_clock::now();
		auto now_t = std::chrono::system_clock::to_time_t(now);

		auto dur = now - std::chrono::system_clock::from_time_t(now_t);
		auto micros = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();

		tv.tv_sec = now_t;
		tv.tv_usec = micros;
		return tv;
	}
}

} // namespace ipxp
