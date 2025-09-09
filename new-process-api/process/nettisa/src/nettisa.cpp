/**
 * @file
 * @brief Plugin for parsing Nettisa flow.
 * @author Josef Koumar koumajos@fit.cvut.cz
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts advanced statistics based on packet lengths,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 * 
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
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

static FieldSchema createNetTimeSeriesSchema(FieldManager& fieldManager, const FieldHandlers<NetTimeSeriesFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("nettisa");

	handlers.insert(NetTimeSeriesFields::NTS_MEAN, schema.addScalarField(
		"NTS_MEAN",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->mean; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_MIN, schema.addScalarField(
		"NTS_MIN",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->min; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_MAX, schema.addScalarField(
		"NTS_MAX",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->max; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_STDEV, schema.addScalarField(
		"NTS_STDEV",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->standardDeviation; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_KURTOSIS, schema.addScalarField(
		"NTS_KURTOSIS",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->kurtosis; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_ROOT_MEAN_SQUARE, schema.addScalarField(
		"NTS_ROOT_MEAN_SQUARE",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->rootMeanSquare; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_AVERAGE_DISPERSION, schema.addScalarField(
		"NTS_AVERAGE_DISPERSION",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->averageDispersion; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_MEAN_SCALED_TIME, schema.addScalarField(
		"NTS_MEAN_SCALED_TIME",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->meanScaledTime; },
	));
	
	handlers.insert(NetTimeSeriesFields::NTS_MEAN_DIFFTIMES, schema.addScalarField(
		"NTS_MEAN_DIFFTIMES",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->meanDifftimes; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_MAX_DIFFTIMES, schema.addScalarField(
		"NTS_MAX_DIFFTIMES",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->maxDifftimes; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_MIN_DIFFTIMES, schema.addScalarField(
		"NTS_MIN_DIFFTIMES",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->minDifftimes; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_TIME_DISTRIBUTION, schema.addScalarField(
		"NTS_TIME_DISTRIBUTION",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->timeDistribution; },
	));

	handlers.insert(NetTimeSeriesFields::NTS_SWITCHING_RATIO, schema.addScalarField(
		"NTS_SWITCHING_RATIO",
		[] (const void* context) { return reinterpret_cast<const NetTimeSeriesData*>(context)->switchingRatio; },
	));

	return schema;
}

NetTimeSeriesPlugin::NetTimeSeriesPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createNetTimeSeriesSchema(manager, m_fieldHandlers);
}

PluginInitResult NetTimeSeriesPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<NetTimeSeriesData*>(pluginContext));
	updateNetTimeSeries(flowContext.flowRecord, flowContext.packet, *pluginData);
	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult NetTimeSeriesPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<NetTimeSeriesData*>(pluginContext);
	updateNetTimeSeries(flowContext.flowRecord, flowContext.packet, *pluginData);
	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

void NetTimeSeriesPlugin::updateNetTimeSeries(FlowRecord& flowRecord, const Packet& packet, NetTimeSeriesData& pluginData) noexcept
{
	const float variationFromMean 
		= static_cast<float>(packet.realLength) - pluginData.mean;
	const float packetsTotal 
		= static_cast<float>(flowRecord.dataForward.packets + flowRecord.dataReverse.packets + 1);
	const float diff = std::max<float>(static_cast<float>(
		packet.timestamp - flowRecord.timeLastUpdate), 0);
	pluginData.processingState.sumPayload += packet.realLength;
	pluginData.processingState.prevTime = packet.timestamp;
	pluginData.mean += (variationFromMean) / packetsTotal;
	pluginData.min = std::min<uint16_t>(pluginData.min, static_cast<uint16_t>(packet.realLength));
	pluginData.max = std::max<uint16_t>(pluginData.max, static_cast<uint16_t>(packet.realLength));
	pluginData.rootMeanSquare += static_cast<float>(std::pow(packet.realLength, 2));
	pluginData.averageDispersion += std::abs(variationFromMean);
	pluginData.kurtosis += static_cast<float>(std::pow(variationFromMean, 4));
	pluginData.meanScaledTime += (static_cast<float>(packet.timestamp - 
		flowRecord.timeCreation) - pluginData.meanScaledTime) / packetsTotal;
	pluginData.meanDifftimes += (diff - pluginData.meanDifftimes) / packetsTotal;
	pluginData.minDifftimes = std::min(pluginData.minDifftimes, diff);
	pluginData.maxDifftimes = std::max(pluginData.maxDifftimes, diff);
	pluginData.timeDistribution += std::abs(pluginData.meanDifftimes - diff);
	if (pluginData.processingState.prevPayload != packet.realLength) {
		pluginData.switchingRatio += 1;
		pluginData.processingState.prevPayload = static_cast<uint16_t>(packet.realLength);
	}
}

PluginExportResult NetTimeSeriesPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	const float packetsTotal = static_cast<float>(
		flowRecord.dataForward.packets + flowRecord.dataReverse.packets);
	if (packetsTotal == 1) {
		return {
			.flowAction = FlowAction::RemovePlugin,
		};
	}
	m_exportData.switchingRatio = m_exportData.switchingRatio / packetsTotal;
	m_exportData.standardDeviation = static_cast<float>(std::pow(
		(m_exportData.rootMeanSquare / packetsTotal) - 
			std::pow(static_cast<float>(m_exportData.processingState.sumPayload) / packetsTotal, 2),
		0.5));
	if (m_exportData.standardDeviation == 0) {
		m_exportData.kurtosis = 0;
	} else {
		m_exportData.kurtosis = static_cast<float>(m_exportData.kurtosis
			/ (packetsTotal * std::pow(m_exportData.standardDeviation, 4)));
	}
	m_exportData.timeDistribution = (m_exportData.timeDistribution / (packetsTotal - 1))
		/ (m_exportData.maxDifftimes - m_exportData.min);
	
	m_exportData.rootMeanSquare = static_cast<float>(std::pow(
		m_exportData.rootMeanSquare / packetsTotal, 0.5));
	m_exportData.averageDispersion = m_exportData.averageDispersion / packetsTotal;

	makeAllFieldsAvailable(flowRecord);
	return {
		.flowAction = FlowAction::NoAction,
	};
}

void NetTimeSeriesPlugin::makeAllFieldsAvailable(const FlowRecord& flowRecord)
{
	m_fieldHandlers[NetTimeSeriesFields::NTS_MEAN].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_MIN].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_MAX].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_STDEV].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_KURTOSIS].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_ROOT_MEAN_SQUARE].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_AVERAGE_DISPERSION].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_MEAN_SCALED_TIME].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_MEAN_DIFFTIMES].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_MIN_DIFFTIMES].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_MAX_DIFFTIMES].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_TIME_DISTRIBUTION].setAsAvailable(flowRecord);
	m_fieldHandlers[NetTimeSeriesFields::NTS_SWITCHING_RATIO].setAsAvailable(flowRecord);
}

void NetTimeSeriesPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<NetTimeSeriesData*>(pluginContext));
}

PluginDataMemoryLayout NetTimeSeriesPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(NetTimeSeriesData),
		.alignment = alignof(NetTimeSeriesData),
	};
}

static const PluginRegistrar<NetTimeSeriesPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	nettisaRegistrar(nettisaPluginManifest);

} // namespace ipxp
