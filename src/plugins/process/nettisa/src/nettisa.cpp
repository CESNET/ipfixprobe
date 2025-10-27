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

#include "nettisaGetters.hpp"

#include <cmath>
#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>

namespace ipxp::process::nettisa {

static const PluginManifest nettisaPluginManifest = {
	.name = "nettisa",
	.description = "Nettisa process plugin for parsing Nettisa flow.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("nettisa", "Parse NetTiSA flow");
			parser.usage(std::cout);
		},
};

static FieldGroup createNetTimeSeriesSchema(
	FieldManager& fieldManager,
	FieldHandlers<NetTimeSeriesFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("nettisa");

	handlers.insert(
		NetTimeSeriesFields::NTS_MEAN,
		schema.addScalarField("NTS_MEAN", getNTSMeanField));

	handlers.insert(NetTimeSeriesFields::NTS_MIN, schema.addScalarField("NTS_MIN", getNTSMinField));

	handlers.insert(NetTimeSeriesFields::NTS_MAX, schema.addScalarField("NTS_MAX", getNTSMaxField));

	handlers.insert(
		NetTimeSeriesFields::NTS_STDEV,
		schema.addScalarField("NTS_STDEV", getNTSStdevField));

	handlers.insert(
		NetTimeSeriesFields::NTS_KURTOSIS,
		schema.addScalarField("NTS_KURTOSIS", getNTSKurtosisField));

	handlers.insert(
		NetTimeSeriesFields::NTS_ROOT_MEAN_SQUARE,
		schema.addScalarField("NTS_ROOT_MEAN_SQUARE", getNTSRootMeanSquareField));

	handlers.insert(
		NetTimeSeriesFields::NTS_AVERAGE_DISPERSION,
		schema.addScalarField("NTS_AVERAGE_DISPERSION", getNTSAverageDispersionField));

	handlers.insert(
		NetTimeSeriesFields::NTS_MEAN_SCALED_TIME,
		schema.addScalarField("NTS_MEAN_SCALED_TIME", getNTSMeanScaledTimeField));

	handlers.insert(
		NetTimeSeriesFields::NTS_MEAN_DIFFTIMES,
		schema.addScalarField("NTS_MEAN_DIFFTIMES", getNTSMeanDifftimesField));

	handlers.insert(
		NetTimeSeriesFields::NTS_MAX_DIFFTIMES,
		schema.addScalarField("NTS_MAX_DIFFTIMES", getNTSMaxDifftimesField));

	handlers.insert(
		NetTimeSeriesFields::NTS_MIN_DIFFTIMES,
		schema.addScalarField("NTS_MIN_DIFFTIMES", getNTSMinDifftimesField));

	handlers.insert(
		NetTimeSeriesFields::NTS_TIME_DISTRIBUTION,
		schema.addScalarField("NTS_TIME_DISTRIBUTION", getNTSTimeDistributionField));

	handlers.insert(
		NetTimeSeriesFields::NTS_SWITCHING_RATIO,
		schema.addScalarField("NTS_SWITCHING_RATIO", getNTSSwitchingRatioField));

	return schema;
}

NetTimeSeriesPlugin::NetTimeSeriesPlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& manager)
{
	createNetTimeSeriesSchema(manager, m_fieldHandlers);
}

OnInitResult NetTimeSeriesPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto& nettisaContext
		= *std::construct_at(reinterpret_cast<NetTimeSeriesContext*>(pluginContext));

	const std::optional<std::size_t> ipPayloadLength
		= getIPPayloadLength(*flowContext.packetContext.packet);
	if (!ipPayloadLength.has_value()) {
		return OnInitResult::Irrelevant;
	}

	updateNetTimeSeries(
		flowContext.flowRecord,
		flowContext.packetContext.packet->timestamp,
		*ipPayloadLength,
		nettisaContext);
	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult NetTimeSeriesPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& nettisaContext = *reinterpret_cast<NetTimeSeriesContext*>(pluginContext);

	const std::optional<std::size_t> ipPayloadLength
		= getIPPayloadLength(*flowContext.packetContext.packet);
	if (!ipPayloadLength.has_value()) {
		return OnUpdateResult::NeedsUpdate;
	}

	updateNetTimeSeries(
		flowContext.flowRecord,
		flowContext.packetContext.packet->timestamp,
		*ipPayloadLength,
		nettisaContext);
	return OnUpdateResult::NeedsUpdate;
}

void NetTimeSeriesPlugin::updateNetTimeSeries(
	FlowRecord& flowRecord,
	const amon::types::Timestamp packetTimestamp,
	const std::size_t ipPayloadLength,
	NetTimeSeriesContext& nettisaContext) noexcept
{
	const float variationFromMean = static_cast<float>(ipPayloadLength) - nettisaContext.mean;
	const float packetsTotal = static_cast<float>(
		flowRecord.directionalData[Direction::Forward].packets
		+ flowRecord.directionalData[Direction::Reverse].packets + 1);
	const float diff = std::max<float>(
		static_cast<float>(packetTimestamp.nanoseconds() - flowRecord.timeLastUpdate.nanoseconds()),
		0);
	nettisaContext.processingState.sumPayload += ipPayloadLength;
	nettisaContext.processingState.prevTime = packetTimestamp;
	nettisaContext.mean += variationFromMean / packetsTotal;
	nettisaContext.min
		= std::min<uint16_t>(nettisaContext.min, static_cast<uint16_t>(ipPayloadLength));
	nettisaContext.max
		= std::max<uint16_t>(nettisaContext.max, static_cast<uint16_t>(ipPayloadLength));
	nettisaContext.rootMeanSquare += static_cast<float>(std::pow(ipPayloadLength, 2));
	nettisaContext.averageDispersion += std::abs(variationFromMean);
	nettisaContext.kurtosis += static_cast<float>(std::pow(variationFromMean, 4));
	nettisaContext.meanScaledTime
		+= static_cast<float>(
			   packetTimestamp.nanoseconds() - flowRecord.timeCreation.nanoseconds()
			   - nettisaContext.meanScaledTime)
		/ packetsTotal;
	nettisaContext.meanDifftimes += (diff - nettisaContext.meanDifftimes) / packetsTotal;
	nettisaContext.minDifftimes = std::min(nettisaContext.minDifftimes, diff);
	nettisaContext.maxDifftimes = std::max(nettisaContext.maxDifftimes, diff);
	nettisaContext.timeDistribution += std::abs(nettisaContext.meanDifftimes - diff);
	if (nettisaContext.processingState.prevPayload != ipPayloadLength) {
		nettisaContext.switchingRatio += 1;
		nettisaContext.processingState.prevPayload = static_cast<uint16_t>(ipPayloadLength);
	}
}

OnExportResult NetTimeSeriesPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	auto& nettisaContext = *reinterpret_cast<NetTimeSeriesContext*>(pluginContext);

	const float packetsTotal = static_cast<float>(
		flowRecord.directionalData[Direction::Forward].packets
		+ flowRecord.directionalData[Direction::Reverse].packets);
	if (packetsTotal == 1) {
		return OnExportResult::Remove;
	}
	nettisaContext.switchingRatio = nettisaContext.switchingRatio / packetsTotal;
	nettisaContext.standardDeviation = static_cast<float>(std::pow(
		(nettisaContext.rootMeanSquare / packetsTotal)
			- std::pow(
				static_cast<float>(nettisaContext.processingState.sumPayload) / packetsTotal,
				2),
		0.5));
	if (nettisaContext.standardDeviation == 0) {
		nettisaContext.kurtosis = 0;
	} else {
		nettisaContext.kurtosis = static_cast<float>(
			nettisaContext.kurtosis
			/ (packetsTotal * std::pow(nettisaContext.standardDeviation, 4)));
	}
	nettisaContext.timeDistribution = (nettisaContext.timeDistribution / (packetsTotal - 1))
		/ (nettisaContext.maxDifftimes - nettisaContext.minDifftimes);

	nettisaContext.rootMeanSquare
		= static_cast<float>(std::pow(nettisaContext.rootMeanSquare / packetsTotal, 0.5));
	nettisaContext.averageDispersion = nettisaContext.averageDispersion / packetsTotal;

	makeAllFieldsAvailable(flowRecord);
	return OnExportResult::NoAction;
}

void NetTimeSeriesPlugin::makeAllFieldsAvailable(const FlowRecord& flowRecord) noexcept
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

void NetTimeSeriesPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<NetTimeSeriesContext*>(pluginContext));
}

PluginDataMemoryLayout NetTimeSeriesPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(NetTimeSeriesContext),
		.alignment = alignof(NetTimeSeriesContext),
	};
}

static const PluginRegistrar<
	NetTimeSeriesPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	nettisaRegistrar(nettisaPluginManifest);

} // namespace ipxp::process::nettisa
