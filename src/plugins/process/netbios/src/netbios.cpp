/**
 * @file
 * @brief Plugin for parsing netbios traffic.
 * @author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Provides a plugin that extracts NetBIOS suffix and name from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "netbios.hpp"

#include "netbiosGetters.hpp"

#include <cmath>
#include <iostream>

#include <dns-utils.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::netbios {

static const PluginManifest netbiosPluginManifest = {
	.name = "netbios",
	.description = "Netbios process plugin for parsing netbios traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("netbios", "Parse netbios traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createNetBIOSSchema(FieldManager& fieldManager, FieldHandlers<NetBIOSFields>& fieldHandlers)
{
	FieldGroup schema = fieldManager.createFieldGroup("netbios");

	fieldHandlers.insert(
		NetBIOSFields::NB_SUFFIX,
		schema.addScalarField("NB_SUFFIX", getNBSuffixField));

	fieldHandlers.insert(NetBIOSFields::NB_NAME, schema.addScalarField("NB_NAME", getNBNameField));

	return schema;
}

NetBIOSPlugin::NetBIOSPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createNetBIOSSchema(manager, m_fieldHandlers);
}

OnInitResult NetBIOSPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr uint8_t NETBIOS_PORT = 137;
	if (flowContext.flowRecord.flowKey.srcPort == NETBIOS_PORT
		|| flowContext.flowRecord.flowKey.dstPort == NETBIOS_PORT) {
		auto& netbiosContext = *std::construct_at(reinterpret_cast<NetBIOSContext*>(pluginContext));
		parseNetBIOS(
			flowContext.flowRecord,
			getPayload(*flowContext.packetContext.packet),
			netbiosContext);
		return OnInitResult::ConstructedFinal;
	}

	return OnInitResult::Irrelevant;
}

constexpr static char compressCharPair(const char first, const char second)
{
	return static_cast<char>(((first - 'A') << 4) | (second - 'A'));
}

void NetBIOSPlugin::parseNetBIOS(
	FlowRecord& flowRecord,
	std::span<const std::byte> payload,
	NetBIOSContext& netbiosContext) noexcept
{
	if (payload.size() < sizeof(dns_hdr) || !netbiosContext.name.empty()) {
		return;
	}

	const std::size_t queryCount
		= reinterpret_cast<const dns_hdr*>(payload.data())->question_rec_cnt;
	if (queryCount == 0) {
		return;
	}

	const uint8_t nameLength = *reinterpret_cast<const uint8_t*>(payload.data() + sizeof(dns_hdr));
	constexpr std::size_t VALID_NB_NAME_LENGTH = 32;
	if (nameLength != VALID_NB_NAME_LENGTH) {
		return;
	}

	auto nameIt = reinterpret_cast<const std::pair<char, char>*>(payload.data());
	for (; reinterpret_cast<const std::byte*>(nameIt) != payload.data() + payload.size() - 2;
		 nameIt++) {
		netbiosContext.name.push_back(compressCharPair(nameIt->first, nameIt->second));
	}
	m_fieldHandlers[NetBIOSFields::NB_NAME].setAsAvailable(flowRecord);

	netbiosContext.suffix = compressCharPair(nameIt->first, nameIt->second);
	m_fieldHandlers[NetBIOSFields::NB_SUFFIX].setAsAvailable(flowRecord);
}

void NetBIOSPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<NetBIOSContext*>(pluginContext));
}

PluginDataMemoryLayout NetBIOSPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(NetBIOSContext),
		.alignment = alignof(NetBIOSContext),
	};
}

static const PluginRegistrar<
	NetBIOSPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	netbiosRegistrar(netbiosPluginManifest);

} // namespace ipxp::process::netbios
