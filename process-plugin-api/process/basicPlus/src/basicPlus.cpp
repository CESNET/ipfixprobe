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

#include "basicPlus.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <packetOfFlowData.hpp>

namespace ipxp {

static const PluginManifest basicPlusPluginManifest = {
	.name = "basicplus",
	.description = "Basicplus process plugin for parsing basicplus traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser(
				"basicplus",
				"Extend basic fields with TTL, TCP window, options, MSS and SYN size");
			parser.usage(std::cout);*/
		},
};

static FieldSchema createBasicPlusSchema()
{
	FieldSchema schema("basicplus");

	schema.addScalarField<uint8_t>(
		"IP_TTL",
		FieldDirection::Forward,
		offsetof(BasicPlusExport, ipTtl.values[Direction::Forward]));
	schema.addScalarField<uint8_t>(
		"IP_TTL_REV",
		FieldDirection::Reverse,
		offsetof(BasicPlusExport, ipTtl.values[Direction::Reverse]));
	schema.addScalarField<uint8_t>(
		"IP_FLG",
		FieldDirection::Forward,
		offsetof(BasicPlusExport, ipFlag.values[Direction::Forward]));
	schema.addScalarField<uint8_t>(
		"IP_FLG_REV",
		FieldDirection::Reverse,
		offsetof(BasicPlusExport, ipFlag.values[Direction::Reverse]));
	schema.addScalarField<uint16_t>(
		"TCP_WIN",
		FieldDirection::Forward,
		offsetof(BasicPlusExport, tcpWindow.values[Direction::Forward]));
	schema.addScalarField<uint16_t>(
		"TCP_WIN_REV",
		FieldDirection::Reverse,
		offsetof(BasicPlusExport, tcpWindow.values[Direction::Reverse]));
	schema.addScalarField<uint64_t>(
		"TCP_OPT",
		FieldDirection::Forward,
		offsetof(BasicPlusExport, tcpOption.values[Direction::Forward]));
	schema.addScalarField<uint64_t>(
		"TCP_OPT_REV",
		FieldDirection::Reverse,
		offsetof(BasicPlusExport, tcpOption.values[Direction::Reverse]));
	schema.addScalarField<uint32_t>(
		"TCP_MSS",
		FieldDirection::Forward,
		offsetof(BasicPlusExport, tcpMss.values[Direction::Forward]));
	schema.addScalarField<uint32_t>(
		"TCP_MSS_REV",
		FieldDirection::Reverse,
		offsetof(BasicPlusExport, tcpMss.values[Direction::Reverse]));
	schema.addScalarField<uint16_t>(
		"TCP_SYN_SIZE",
		FieldDirection::DirectionalIndifferent,
		offsetof(BasicPlusExport, tcpSynSize));

	schema.addBiflowPair("IP_TTL", "IP_TTL_REV");
	schema.addBiflowPair("IP_FLG", "IP_FLG_REV");
	schema.addBiflowPair("TCP_WIN", "TCP_WIN_REV");
	schema.addBiflowPair("TCP_OPT", "TCP_OPT_REV");
	schema.addBiflowPair("TCP_MSS", "TCP_MSS_REV");

	return schema;
}

BasicPlusPlugin::BasicPlusPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createBasicPlusSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	
	m_fieldHandlers[BasicPlusFields::IP_TTL] = schemaHandler.getFieldHandler("IP_TTL");
	m_fieldHandlers[BasicPlusFields::IP_TTL_REV] = schemaHandler.getFieldHandler("IP_TTL_REV");
	m_fieldHandlers[BasicPlusFields::IP_FLG] = schemaHandler.getFieldHandler("IP_FLG");
	m_fieldHandlers[BasicPlusFields::IP_FLG_REV] = schemaHandler.getFieldHandler("IP_FLG_REV");
	m_fieldHandlers[BasicPlusFields::TCP_WIN] = schemaHandler.getFieldHandler("TCP_WIN");
	m_fieldHandlers[BasicPlusFields::TCP_WIN_REV] = schemaHandler.getFieldHandler("TCP_WIN_REV");
	m_fieldHandlers[BasicPlusFields::TCP_OPT] = schemaHandler.getFieldHandler("TCP_OPT");
	m_fieldHandlers[BasicPlusFields::TCP_OPT_REV] = schemaHandler.getFieldHandler("TCP_OPT_REV");
	m_fieldHandlers[BasicPlusFields::TCP_MSS] = schemaHandler.getFieldHandler("TCP_MSS");
	m_fieldHandlers[BasicPlusFields::TCP_MSS_REV] = schemaHandler.getFieldHandler("TCP_MSS_REV");
	m_fieldHandlers[BasicPlusFields::TCP_SYN_SIZE] = schemaHandler.getFieldHandler("TCP_SYN_SIZE");
}

FlowAction BasicPlusPlugin::onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
{

	m_exportData.ipTtl[Direction::Forward] = packet.ipTtl;
	m_fieldHandlers[BasicPlusFields::IP_TTL].setAsAvailable(flowRecord);

	m_exportData.ipFlag[Direction::Forward] = packet.ipFlags;
	m_fieldHandlers[BasicPlusFields::IP_FLG].setAsAvailable(flowRecord);

	m_exportData.tcpWindow[Direction::Forward] = packet.tcpWindow;
	m_fieldHandlers[BasicPlusFields::TCP_WIN].setAsAvailable(flowRecord);

	m_exportData.tcpOption[Direction::Forward] = packet.tcpOptions;
	m_fieldHandlers[BasicPlusFields::TCP_OPT].setAsAvailable(flowRecord);

	m_exportData.tcpMss[Direction::Forward] = packet.tcpMss;
	m_fieldHandlers[BasicPlusFields::TCP_MSS].setAsAvailable(flowRecord);

	if (packet.tcpFlags.flags.synchronize) { // check if SYN packet
		m_exportData.tcpSynSize = packet.ipLength;
		m_fieldHandlers[BasicPlusFields::TCP_SYN_SIZE].setAsAvailable(flowRecord);
	}

	return FlowAction::RequestTrimmedData;
}

FlowAction BasicPlusPlugin::onFlowUpdate(FlowRecord& flowRecord, 
	const Packet& packet, const PacketOfFlowData& data)
{
	m_exportData.ipTtl[Direction::Forward] 
		= std::min(m_exportData.ipTtl[Direction::Forward], packet.ipTtl);
	
	if (data.packetDirection == Direction::Reverse) {
		m_exportData.ipTtl[Direction::Reverse] = packet.ipTtl;
		m_fieldHandlers[BasicPlusFields::IP_TTL_REV].setAsAvailable(flowRecord);

		m_exportData.ipFlag[Direction::Reverse] = packet.ipFlags;
		m_fieldHandlers[BasicPlusFields::IP_FLG_REV].setAsAvailable(flowRecord);
		
		m_exportData.tcpWindow[Direction::Reverse] = packet.tcpWindow;
		m_fieldHandlers[BasicPlusFields::TCP_WIN_REV].setAsAvailable(flowRecord);
		
		m_exportData.tcpOption[Direction::Reverse] = packet.tcpOptions;
		m_fieldHandlers[BasicPlusFields::TCP_OPT_REV].setAsAvailable(flowRecord);

		m_exportData.tcpMss[Direction::Reverse] = packet.tcpMss;
		m_fieldHandlers[BasicPlusFields::TCP_MSS_REV].setAsAvailable(flowRecord);

		m_exportData.processingState.destinationFilled = true;
	}

	m_exportData.tcpOption[data.packetDirection] |= packet.tcpOptions;

	return FlowAction::RequestTrimmedData;
}

void BasicPlusPlugin::onFlowExport() {}

ProcessPlugin* BasicPlusPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<BasicPlusPlugin*>(constructAtAddress), *this);
}

std::string BasicPlusPlugin::getName() const { 
	return basicPlusPluginManifest.name; 
}

const void* BasicPlusPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<BasicPlusPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	basicPlusRegistrar(basicPlusPluginManifest);

} // namespace ipxp
