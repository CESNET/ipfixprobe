/**
 * \file
 * \brief Implementation of the DpdkPortTelemetry class and related helper functions
 * \author Pavel Siska <siska@cesnet.cz>
 * \date 2024
 */
/*
 * Copyright (C) 2024 CESNET
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

#include "dpdkPortTelemetry.hpp"

#include "dpdkCompat.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <limits>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <rte_ethdev.h>
#include <rte_version.h>

namespace ipxp {

static struct rte_eth_dev_info getDeviceInfo(uint16_t portId)
{
	struct rte_eth_dev_info devInfo;

	const int ret = rte_eth_dev_info_get(portId, &devInfo);
	if (ret < 0) {
		throw std::runtime_error("getDeviceInfo() has failed");
	}

	return devInfo;
}

static std::string getDeviceNameByPortId(uint16_t portId)
{
	std::array<char, RTE_ETH_NAME_MAX_LEN> deviceName;

	const int ret = rte_eth_dev_get_name_by_port(portId, deviceName.data());
	if (ret < 0) {
		return "";
	}

	return {deviceName.data()};
}

static std::string getRssHashKeyByPortId(uint16_t portId)
{
	uint8_t rssHashKeySize = 0;
	try {
		rssHashKeySize = getDeviceInfo(portId).hash_key_size;
	} catch (const std::exception& ex) {
		return "";
	}

	std::vector<uint8_t> rssHashKey(rssHashKeySize);

	struct rte_eth_rss_conf rssConf = {};
	rssConf.rss_key = rssHashKey.data();
	rssConf.rss_key_len = rssHashKeySize;

	const int ret = rte_eth_dev_rss_hash_conf_get(portId, &rssConf);
	if (ret < 0) {
		return "";
	}

	std::ostringstream oss;
	for (const auto& byte : rssHashKey) {
		oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
	}
	return oss.str();
}

static std::string getRssHashByPortId(uint16_t portId)
{
	struct rte_eth_rss_conf rssConf = {};
	rssConf.rss_key = nullptr;
	rssConf.rss_key_len = 0;

	const int ret = rte_eth_dev_rss_hash_conf_get(portId, &rssConf);
	if (ret < 0) {
		return "";
	}

	std::vector<std::string> rssHashes;

	if ((rssConf.rss_hf & RTE_ETH_RSS_IPV4) != 0U) {
		rssHashes.emplace_back("IPV4");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_FRAG_IPV4) != 0U) {
		rssHashes.emplace_back("FRAG_IPV4");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_TCP) != 0U) {
		rssHashes.emplace_back("NONFRAG_IPV4_TCP");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_UDP) != 0U) {
		rssHashes.emplace_back("NONFRAG_IPV4_UDP");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_SCTP) != 0U) {
		rssHashes.emplace_back("NONFRAG_IPV4_SCTP");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_OTHER) != 0U) {
		rssHashes.emplace_back("NONFRAG_IPV4_OTHER");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_IPV6) != 0U) {
		rssHashes.emplace_back("IPV6");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_FRAG_IPV6) != 0U) {
		rssHashes.emplace_back("FRAG_IPV6");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_NONFRAG_IPV6_TCP) != 0U) {
		rssHashes.emplace_back("NONFRAG_IPV6_TCP");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_NONFRAG_IPV6_UDP) != 0U) {
		rssHashes.emplace_back("NONFRAG_IPV6_UDP");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_NONFRAG_IPV6_SCTP) != 0U) {
		rssHashes.emplace_back("NONFRAG_IPV6_SCTP");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_NONFRAG_IPV6_OTHER) != 0U) {
		rssHashes.emplace_back("NONFRAG_IPV6_OTHER");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_L2_PAYLOAD) != 0U) {
		rssHashes.emplace_back("L2_PAYLOAD");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_IPV6_EX) != 0U) {
		rssHashes.emplace_back("IPV6_EX");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_IPV6_TCP_EX) != 0U) {
		rssHashes.emplace_back("IPV6_TCP_EX");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_IPV6_UDP_EX) != 0U) {
		rssHashes.emplace_back("IPV6_UDP_EX");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_PORT) != 0U) {
		rssHashes.emplace_back("PORT");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_VXLAN) != 0U) {
		rssHashes.emplace_back("VXLAN");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_GENEVE) != 0U) {
		rssHashes.emplace_back("GENEVE");
	}
	if ((rssConf.rss_hf & RTE_ETH_RSS_NVGRE) != 0U) {
		rssHashes.emplace_back("NVGRE");
	}
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
	if ((rssConf.rss_hf & RTE_ETH_RSS_MPLS) != 0U) {
		rssHashes.emplace_back("MPLS");
	}
#endif

	const std::string concatenatedRssHash = std::accumulate(
		rssHashes.begin(),
		rssHashes.end(),
		std::string {},
		[](const std::string& str1, const std::string& str2) {
			return str1.empty() ? str2 : str1 + ", " + str2;
		});

	return concatenatedRssHash;
}

static telemetry::Dict getDeviceStatsByPortId(uint16_t portId)
{
	struct rte_eth_stats stats;
	const int ret = rte_eth_stats_get(portId, &stats);
	if (ret < 0) {
		return {};
	}

	telemetry::Dict statsDict = {
		{"rx-ipackets", stats.ipackets},
		{"rx-ibytes", stats.ibytes},
		{"rx-imissed", stats.imissed},
		{"rx-ierrors", stats.ierrors},
		{"rx-nombuf", stats.rx_nombuf},
		{"tx-opackets", stats.opackets},
		{"tx-obytes", stats.obytes},
		{"tx-oerrors", stats.oerrors},
	};

	return statsDict;
}

static telemetry::Dict getDeviceQueueStatsByPortId(uint16_t portId)
{
	struct rte_eth_stats stats;
	const int ret = rte_eth_stats_get(portId, &stats);
	if (ret < 0) {
		return {};
	}

	const rte_eth_dev_info devInfo = getDeviceInfo(portId);

	uint16_t maxQueuesCount;
	if (RTE_ETHDEV_QUEUE_STAT_CNTRS > std::numeric_limits<uint16_t>::max()) {
		maxQueuesCount = std::numeric_limits<uint16_t>::max();
	} else {
		maxQueuesCount = static_cast<uint16_t>(RTE_ETHDEV_QUEUE_STAT_CNTRS);
	}

	const uint16_t rxQueuesCount = std::min(maxQueuesCount, devInfo.nb_rx_queues);
	const uint16_t txQueuesCount = std::min(maxQueuesCount, devInfo.nb_tx_queues);

	telemetry::Dict dict;

	for (uint16_t queueId = 0; queueId < rxQueuesCount; queueId++) {
		const std::string queueIdName = std::to_string(queueId);
		dict[queueIdName + "-rx-ipackets"] = stats.q_ipackets[queueId];
		dict[queueIdName + "-rx-ibytes"] = stats.q_ibytes[queueId];
		dict[queueIdName + "-rx-ierrors"] = stats.q_errors[queueId];
	}

	for (uint16_t queueId = 0; queueId < txQueuesCount; queueId++) {
		const std::string queueIdName = std::to_string(queueId);
		dict[queueIdName + "-tx-opackets"] = stats.q_opackets[queueId];
		dict[queueIdName + "-tx-obytes"] = stats.q_obytes[queueId];
	}

	return dict;
}

static telemetry::Dict getDeviceXStatsByPortId(uint16_t portId)
{
	int ret;
	ret = rte_eth_xstats_get_names(portId, nullptr, 0);
	if (ret < 0) {
		return {};
	}

	const auto count = static_cast<unsigned int>(ret);

	std::vector<rte_eth_xstat_name> xstatsNames(count);
	std::vector<rte_eth_xstat> xstats(count);

	ret = rte_eth_xstats_get_names(portId, xstatsNames.data(), count);
	if (ret < 0) {
		return {};
	}

	ret = rte_eth_xstats_get(portId, xstats.data(), count);
	if (ret < 0) {
		return {};
	}

	telemetry::Dict dict;
	for (unsigned int idx = 0; idx < count; idx++) {
		dict[xstatsNames[idx].name] = xstats[idx].value;
	}

	return dict;
}

struct AppFsFile {
	std::string name;
	telemetry::FileOps ops;
};

static std::vector<AppFsFile> getAppFsFiles(uint16_t portId)
{
	std::vector<AppFsFile> files = {
        {
            .name = "devname",
            .ops = {
                .read = [portId]() { return getDeviceNameByPortId(portId); },
            },
        },
        {
            .name = "rss_hash_key",
            .ops = {
                .read = [portId]() { return getRssHashKeyByPortId(portId); },
            },
        },
        {
            .name = "rss_hash",
            .ops = {
                .read = [portId]() { return getRssHashByPortId(portId); },
            },
        },
        {
            .name = "devstats",
            .ops = {
                .read = [portId]() { return getDeviceStatsByPortId(portId); },
            },
        },
        {
            .name = "devstats_queues",
            .ops = {
                .read = [portId]() { return getDeviceQueueStatsByPortId(portId); },
            },
        },
        {
            .name = "devxstats",
            .ops = {
                .read = [portId]() { return getDeviceXStatsByPortId(portId); },
            },
        },

    };
	return files;
}

DpdkPortTelemetry::DpdkPortTelemetry(
	uint16_t portId,
	const std::shared_ptr<telemetry::Directory>& dir)
	: M_PORT_ID(portId)
{
	for (auto [name, ops] : getAppFsFiles(M_PORT_ID)) {
		if (dir->getEntry(name)) {
			continue;
		}
		auto file = dir->addFile(name, ops);
		m_holder.add(file);
	}
}

} // namespace ipxp
