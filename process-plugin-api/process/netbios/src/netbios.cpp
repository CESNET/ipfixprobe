/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "netbios.hpp"

#include <iostream>
#include <cmath>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <dns-utils.hpp>

namespace ipxp {

static const PluginManifest netbiosPluginManifest = {
	.name = "netbios",
	.description = "Netbios process plugin for parsing netbios traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("netbios", "Parse netbios traffic");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<NetBIOSFields>> fields = {
	{NetBIOSFields::NB_NAME, "NB_NAME"},
	{NetBIOSFields::NB_SUFFIX, "NB_SUFFIX"},
};

static FieldSchema createNetBIOSSchema()
{
	FieldSchema schema("netbios");

	schema.addScalarField<uint8_t>(
		"NB_SUFFIX",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetBIOSExport, suffix));

	/// TODO EXPORT STRING

	schema.addVectorField<std::string>(
		"NB_NAME",
		FieldDirection::DirectionalIndifferent,
		[](const void* thisPtr) -> std::span<const std::string> {
			return std::span<const std::string>(&reinterpret_cast<const NetBIOSExport*>(thisPtr)
				->name, 1);
		});

	return schema;
}

NetBIOSPlugin::NetBIOSPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createNetBIOSSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction NetBIOSPlugin::onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
{
	if (packet.flowKey.srcPort == 137 || packet.flowKey.dstPort == 137) {
		return parseNetBIOS(flowRecord, packet.payload);
	}
	return FlowAction::RequestNoData;
}

FlowAction NetBIOSPlugin::onFlowUpdate(FlowRecord& flowRecord, const Packet& packet)
{
	return parseNetBIOS(flowRecord, packet.payload);
}

constexpr static
char compressCharPair(const char first, const char second)
{
	return static_cast<char>(((first - 'A') << 4) | (second - 'A'));
}

FlowAction NetBIOSPlugin::parseNetBIOS(FlowRecord& flowRecord, 
	std::span<const std::byte> payload) noexcept
{
	if (payload.size() < sizeof(dns_hdr) || !m_exportData.name.empty()) {
		return FlowAction::RequestNoData;
	}

	const std::size_t queryCount 
		= reinterpret_cast<const dns_hdr*>(payload.data())->question_rec_cnt;
	if (queryCount == 0) {
		return FlowAction::RequestNoData;
	}

	const uint8_t nameLength 
		= *reinterpret_cast<const uint8_t*>(payload.data() + sizeof(dns_hdr));
	constexpr std::size_t VALID_NB_NAME_LENGTH = 32;
	if (nameLength != VALID_NB_NAME_LENGTH) {
		return FlowAction::RequestNoData;
	}

	auto nameIt = reinterpret_cast<const std::pair<char, char>*>(payload.data());
	for (; reinterpret_cast<const std::byte*>(nameIt) 
			!= payload.data() + payload.size() - 2; nameIt++) {
		m_exportData.name.push_back(compressCharPair(nameIt->first, nameIt->second));
	}
	m_fieldHandlers[NetBIOSFields::NB_NAME].setAsAvailable(flowRecord);

	m_exportData.suffix = compressCharPair(nameIt->first, nameIt->second);
	m_fieldHandlers[NetBIOSFields::NB_SUFFIX].setAsAvailable(flowRecord);

	return FlowAction::RequestNoData;
}

ProcessPlugin* NetBIOSPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<NetBIOSPlugin*>(constructAtAddress), *this);
}

std::string NetBIOSPlugin::getName() const { 
	return netbiosPluginManifest.name; 
}

const void* NetBIOSPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<NetBIOSPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	netbiosRegistrar(netbiosPluginManifest);

} // namespace ipxp
