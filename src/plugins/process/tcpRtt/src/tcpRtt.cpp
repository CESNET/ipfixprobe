/**
 * @file
 * @brief Plugin for accounting round trip time of tcp handshakes.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tcpRtt.hpp"

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

namespace ipxp {

static const PluginManifest tcpRttPluginManifest = {
	.name = "tcprtt",
	.description = "Process plugin to obtain round trip time of TCP connection.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("tcprtt", "Calculate tcp rtt");
			parser.usage(std::cout);
		},
};

TCPRTTPlugin::TCPRTTPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

OptionsParser* TCPRTTPlugin::get_parser() const
{
	return new OptionsParser("tcprtt", "Calculate tcp rtt");
}

std::string TCPRTTPlugin::get_name() const
{
	return "tcprtt";
}

RecordExtTCPRTT* TCPRTTPlugin::get_ext() const
{
	return new RecordExtTCPRTT(m_pluginID);
}

void TCPRTTPlugin::init([[maybe_unused]] const char* params) {}

TCPRTTPlugin::TCPRTTPlugin(const TCPRTTPlugin& other) noexcept
	: ProcessPlugin(other.m_pluginID)
{
}

ProcessPlugin* TCPRTTPlugin::copy()
{
	return new TCPRTTPlugin(*this);
}

int TCPRTTPlugin::post_create(Flow& rec, const Packet& pkt)
{
	if (m_prealloced_extension == nullptr) {
		m_prealloced_extension.reset(get_ext());
	}

	if (pkt.ip_proto == IPPROTO_TCP) {
		rec.add_extension(m_prealloced_extension.release());
	}

	update_tcp_rtt_record(rec, pkt);
	return 0;
}

int TCPRTTPlugin::pre_update(Flow& rec, Packet& pkt)
{
	update_tcp_rtt_record(rec, pkt);
	return 0;
}

constexpr static inline bool is_tcp_syn(uint8_t tcp_flags) noexcept
{
	return tcp_flags & 0b10;
}

constexpr static inline bool is_tcp_syn_ack(uint8_t tcp_flags) noexcept
{
	return (tcp_flags & 0b10) && (tcp_flags & 0b10000);
}

void TCPRTTPlugin::update_tcp_rtt_record(Flow& rec, const Packet& pkt) noexcept
{
	auto* extension = static_cast<RecordExtTCPRTT*>(rec.get_extension(m_pluginID));

	if (extension != nullptr && is_tcp_syn_ack(pkt.tcp_flags)) {
		extension->tcp_synack_timestamp = pkt.ts;
	} else if (extension != nullptr && is_tcp_syn(pkt.tcp_flags)) {
		extension->tcp_syn_timestamp = pkt.ts;
	}
}

static const PluginRegistrar<TCPRTTPlugin, ProcessPluginFactory>
	tcpRttRegistrar(tcpRttPluginManifest);

} // namespace ipxp
