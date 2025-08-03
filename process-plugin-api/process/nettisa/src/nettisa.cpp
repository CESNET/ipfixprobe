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

#include "nettisa.hpp"

#include <iostream>
#include <cmath>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

namespace ipxp {

static const PluginManifest nettisaPluginManifest = {
	.name = "nettisa",
	.description = "Nettisa process plugin for parsing Nettisa flow.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("nettisa", "Parse NetTiSA flow");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<NetTimeSeriesFields>> fields = {
	{NetTimeSeriesFields::NTS_MEAN, "NTS_MEAN"},
	{NetTimeSeriesFields::NTS_MIN, "NTS_MIN"},
	{NetTimeSeriesFields::NTS_MAX, "NTS_MAX"},
	{NetTimeSeriesFields::NTS_STDEV, "NTS_STDEV"},
	{NetTimeSeriesFields::NTS_KURTOSIS, "NTS_KURTOSIS"},
	{NetTimeSeriesFields::NTS_ROOT_MEAN_SQUARE, "NTS_ROOT_MEAN_SQUARE"},
	{NetTimeSeriesFields::NTS_AVERAGE_DISPERSION, "NTS_AVERAGE_DISPERSION"},
	{NetTimeSeriesFields::NTS_MEAN_SCALED_TIME, "NTS_MEAN_SCALED_TIME"},
	{NetTimeSeriesFields::NTS_MEAN_DIFFTIMES, "NTS_MEAN_DIFFTIMES"},
	{NetTimeSeriesFields::NTS_MIN_DIFFTIMES, "NTS_MIN_DIFFTIMES"},
	{NetTimeSeriesFields::NTS_MAX_DIFFTIMES, "NTS_MAX_DIFFTIMES"},
	{NetTimeSeriesFields::NTS_TIME_DISTRIBUTION, "NTS_TIME_DISTRIBUTION"},
	{NetTimeSeriesFields::NTS_SWITCHING_RATIO, "NTS_SWITCHING_RATIO"},
};

static FieldSchema createNetTimeSeriesSchema()
{
	FieldSchema schema("nettisa");

	schema.addScalarField<float>(
		"NTS_MEAN",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, mean));
	
	schema.addScalarField<uint16_t>(
		"NTS_MIN",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, min));
	
	schema.addScalarField<uint16_t>(
		"NTS_MAX",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, max));
	
	schema.addScalarField<float>(
		"NTS_STDEV",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, stdev));
	
	schema.addScalarField<float>(
		"NTS_KURTOSIS",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, kurtosis));
	
	schema.addScalarField<float>(
		"NTS_ROOT_MEAN_SQUARE",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, rootMeanSquare));
	
	schema.addScalarField<float>(
		"NTS_AVERAGE_DISPERSION",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, averageDispersion));
	
	schema.addScalarField<float>(
		"NTS_MEAN_SCALED_TIME",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, meanScaledTime));
	
	schema.addScalarField<float>(
		"NTS_MEAN_DIFFTIMES",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, meanDifftimes));
	
	schema.addScalarField<float>(
		"NTS_MAX_DIFFTIMES",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, maxDifftimes));
	
	schema.addScalarField<float>(
		"NTS_MIN_DIFFTIMES",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, minDifftimes));
	
	schema.addScalarField<float>(
		"NTS_TIME_DISTRIBUTION",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, timeDistribution));
	
	schema.addScalarField<float>(
		"NTS_SWITCHING_RATIO",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetTimeSeriesExport, switchingRatio));

	return schema;
}

void NetTimeSeriesPlugin::makeAllFieldsAvailable(FlowRecord& flowRecord) noexcept
{
	for (const auto& [field, _] : fields) {
		m_fieldHandlers[field].setAsAvailable(flowRecord);
	}
}

void NetTimeSeriesPlugin::makeAllFieldsUnavailable(FlowRecord& flowRecord) noexcept
{
	for (const auto& [field, _] : fields) {
		m_fieldHandlers[field].setAsUnavailable(flowRecord);
	}
}

NetTimeSeriesPlugin::NetTimeSeriesPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createNetTimeSeriesSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction NetTimeSeriesPlugin::onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
{
	updateNetTimeSeries(flowRecord, packet);
	makeAllFieldsAvailable(flowRecord);
	return FlowAction::RequestFullData;
}

FlowAction NetTimeSeriesPlugin::onFlowUpdate(FlowRecord& flowRecord, 
	const Packet& packet)
{
	updateNetTimeSeries(flowRecord, packet);
	return FlowAction::RequestFullData;
}

void NetTimeSeriesPlugin::updateNetTimeSeries(FlowRecord& flowRecord,
	const Packet& packet) noexcept
{
	const float variationFromMean 
		= static_cast<float>(packet.realLength) - m_exportData.mean;
	const float packetsTotal 
		= static_cast<float>(flowRecord.dataForward.packets + flowRecord.dataReverse.packets + 1);
	const float diff = std::max<float>(static_cast<float>(
		packet.timestamp - flowRecord.timeLastUpdate), 0);
	m_exportData.processingState.sumPayload += packet.realLength;
	m_exportData.processingState.prevTime = packet.timestamp;
	m_exportData.mean += (variationFromMean) / packetsTotal;
	m_exportData.min = std::min<uint16_t>(m_exportData.min, static_cast<uint16_t>(packet.realLength));
	m_exportData.max = std::max<uint16_t>(m_exportData.max, static_cast<uint16_t>(packet.realLength));
	m_exportData.rootMeanSquare += static_cast<float>(std::pow(packet.realLength, 2));
	m_exportData.averageDispersion += std::abs(variationFromMean);
	m_exportData.kurtosis += static_cast<float>(std::pow(variationFromMean, 4));
	m_exportData.meanScaledTime += (static_cast<float>(packet.timestamp - 
		flowRecord.timeCreation) - m_exportData.meanScaledTime) / packetsTotal;
	m_exportData.meanDifftimes += (diff - m_exportData.meanDifftimes) / packetsTotal;
	m_exportData.minDifftimes = std::min(m_exportData.minDifftimes, diff);
	m_exportData.maxDifftimes = std::max(m_exportData.maxDifftimes, diff);
	m_exportData.timeDistribution += std::abs(m_exportData.meanDifftimes - diff);
	if (m_exportData.processingState.prevPayload != packet.realLength) {
		m_exportData.switchingRatio += 1;
		m_exportData.processingState.prevPayload = static_cast<uint16_t>(packet.realLength);
	}
}

void NetTimeSeriesPlugin::onFlowExport(FlowRecord& flowRecord) {
	const float packetsTotal = static_cast<float>(
		flowRecord.dataForward.packets + flowRecord.dataReverse.packets);
	if (packetsTotal == 1) {
		makeAllFieldsUnavailable(flowRecord);
		return;
	}
	m_exportData.switchingRatio = m_exportData.switchingRatio / packetsTotal;
	m_exportData.stdev = static_cast<float>(std::pow(
		(m_exportData.rootMeanSquare / packetsTotal) - 
			std::pow(static_cast<float>(m_exportData.processingState.sumPayload) / packetsTotal, 2),
		0.5));
	if (m_exportData.stdev == 0) {
		m_exportData.kurtosis = 0;
	} else {
		m_exportData.kurtosis = static_cast<float>(m_exportData.kurtosis 
			/ (packetsTotal * std::pow(m_exportData.stdev, 4)));
	}
	m_exportData.timeDistribution = (m_exportData.timeDistribution / (packetsTotal - 1))
		/ (m_exportData.maxDifftimes - m_exportData.min);
	
	m_exportData.rootMeanSquare = static_cast<float>(std::pow(
		m_exportData.rootMeanSquare / packetsTotal, 0.5));
	m_exportData.averageDispersion = m_exportData.averageDispersion / packetsTotal;
}

ProcessPlugin* NetTimeSeriesPlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<NetTimeSeriesPlugin*>(constructAtAddress), *this);
}

std::string NetTimeSeriesPlugin::getName() const { 
	return nettisaPluginManifest.name; 
}

const void* NetTimeSeriesPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<NetTimeSeriesPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	nettisaRegistrar(nettisaPluginManifest);

} // namespace ipxp
