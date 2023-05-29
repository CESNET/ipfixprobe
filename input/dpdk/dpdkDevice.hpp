/**
 * \file
 * \brief Declaration of the DpdkDevice class.
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

#pragma once

#include "dpdkMbuf.hpp"

#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <vector>

namespace ipxp {

/**
 * @brief The DpdkDevice class represents a DPDK (Data Plane Development Kit) device.
 *        It provides functionality to manage and interact with the DPDK device.
 */
class DpdkDevice {
public:
	/**
	 * @brief Constructs a DpdkDevice object with the specified parameters.
	 * @param portID The ID of the DPDK port to be used.
	 * @param rxQueueCount The number of receive queues to be configured.
	 * @param memPoolSize The size of the memory pool for packet buffers.
	 * @param mbufsCount The number of mbufs (packet buffers) to be allocated.
	 */
	DpdkDevice(uint16_t portID, uint16_t rxQueueCount, uint16_t memPoolSize, uint16_t mbufsCount);

	/**
	 * @brief Receives packets from the specified receive queue of the DPDK device.
	 * @param dpdkMuf A reference to a DpdkMbuf object to store the received packets.
	 * @param rxQueueID The ID of the receive queue from which to receive packets.
	 * @return The number of packets received.
	 */
	uint16_t receive(DpdkMbuf& dpdkMuf, uint16_t rxQueueID);

	/**
	 * @brief Retrieves the packet timestamp from the given mbuf.
	 * @param mbuf The rte_mbuf structure representing the received packet.
	 * @return The timestamp of the packet.
	 */
	timeval getPacketTimestamp(rte_mbuf* mbuf);

	/**
	 * @brief Destructs the DpdkDevice object.
	 *        Stops and closes the DPDK port associated with the device.
	 */
	~DpdkDevice();

private:
	void validatePort();
	void recognizeDriver();
	void configurePort();
	rte_eth_conf createPortConfig();
	void initMemPools(uint16_t memPoolSize);
	void setupRxQueues();
	void configureRSS();
	void enablePort();
	void createRteMempool(uint16_t mempoolSize);
	void setRxTimestampDynflag();
	void registerRxTimestamp();

	std::vector<rte_mempool*> m_memPools;
    uint16_t m_portID;
	uint16_t m_rxQueueCount;
	uint16_t m_txQueueCount;
	uint16_t m_mBufsCount;
	bool m_isNfbDpdkDriver;
	bool m_supportedRSS;
	bool m_supportedHWTimestamp;
	int m_rxTimestampOffset;
	int m_rxTimestampDynflag;

};

} // namespace ipxp