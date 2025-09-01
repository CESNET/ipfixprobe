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

#include "ntp.hpp"

#include <iostream>
#include <arpa/inet.h>
#include <format>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

namespace ipxp {

using namespace std::string_view_literals;

static const PluginManifest ntpPluginManifest = {
	.name = "ntp",
	.description = "Ntp process plugin for parsing ntp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("ntp", "Parse NTP traffic");
			parser.usage(std::cout);*/
		},
};

static FieldSchema createNetworkTimeSchema(FieldManager& fieldManager, FieldHandlers<NetworkTimeFields>& handlers)
{
	FieldSchema schema = fieldManager.createFieldSchema("ntp");

	handlers.insert(NetworkTimeFields::NTP_LEAP, schema.addScalarField(
		"NTP_LEAP",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->leap; },
	));

	handlers.insert(NetworkTimeFields::NTP_VERSION, schema.addScalarField(
		"NTP_VERSION",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->version; },
	));

	handlers.insert(NetworkTimeFields::NTP_MODE, schema.addScalarField(
		"NTP_MODE",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->mode; },
	));

	handlers.insert(NetworkTimeFields::NTP_STRATUM, schema.addScalarField(
		"NTP_STRATUM",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->stratum; },
	));

	handlers.insert(NetworkTimeFields::NTP_POLL, schema.addScalarField(
		"NTP_POLL",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->poll; },
	));

	handlers.insert(NetworkTimeFields::NTP_DELAY, schema.addScalarField(
		"NTP_DELAY",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->delay; },
	));

	handlers.insert(NetworkTimeFields::NTP_DISPERSION, schema.addScalarField(
		"NTP_DISPERSION",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->dispersion; },
	));

	handlers.insert(NetworkTimeFields::NTP_REF_ID, schema.addScalarField(
		"NTP_REF_ID",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->referenceId; },
	));

	handlers.insert(NetworkTimeFields::NTP_REF, schema.addScalarField(
		"NTP_REF",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->reference; },
	));

	handlers.insert(NetworkTimeFields::NTP_ORIG, schema.addScalarField(
		"NTP_ORIG",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->origin; },
	));

	handlers.insert(NetworkTimeFields::NTP_RECV, schema.addScalarField(
		"NTP_RECV",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->receive; },
	));

	handlers.insert(NetworkTimeFields::NTP_SENT, schema.addScalarField(
		"NTP_SENT",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeExport*>(context)->sent; },
	));

	return schema;
}

NetworkTimePlugin::NetworkTimePlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createNetworkTimeSchema(manager, m_fieldHandlers);
}

PluginInitResult NetworkTimePlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	if (flowContext.packet.flowKey.srcPort == 123 || flowContext.packet.flowKey.dstPort == 123) {
		auto* pluginData = std::construct_at(reinterpret_cast<NetworkTimeData*>(pluginContext));
		if (!parseNTP(flowRecord, flowContext.packet.payload, *pluginData)) {
			return {
				.constructionState = ConstructionState::Constructed,
				.updateRequirement = UpdateRequirement::NoUpdateNeeded,
				.flowAction = FlowAction::RemovePlugin,
			};
		}
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::Flush,
		};
	}
	return {
		.constructionState = ConstructionState::NotConstructed,
		.updateRequirement = UpdateRequirement::NoUpdateNeeded,
		.flowAction = FlowAction::RemovePlugin,
	};
}

static
boost::static_string<NetworkTimeExport::MAX_TIMESTAMP_AS_TEXT_LENGTH> 
ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)> timestampSpan)
{
	const double seconds 
		= static_cast<double>(ntohl(*reinterpret_cast<const uint32_t*>(timestampSpan.data())));
	const double fractions = static_cast<double>(ntohl(
		*reinterpret_cast<const uint32_t*>(
			timestampSpan.data() + sizeof(uint32_t)))) * (1.0 / (1ULL << 32));

	boost::static_string<NetworkTimeExport::MAX_TIMESTAMP_AS_TEXT_LENGTH> res;
	std::format_to(std::back_inserter(res), "{}", seconds + fractions);
	return res;
}

bool
NetworkTimePlugin::fillNetworkTimeHeader(NetworkTimeHeader networkTimeHeader) noexcept
{
	m_exportData.leap = networkTimeHeader.bitfields.leap;

	if (networkTimeHeader.bitfields.version != 4) {
		//Error: Bad number of version or NTP exploit detected
		return false;
	}
	m_exportData.version = networkTimeHeader.bitfields.version;

	if (networkTimeHeader.bitfields.mode < 3 || 
			networkTimeHeader.bitfields.mode > 4) {
		// Error: Bad NTP mode or NTP exploit detected.
		return false;
	}
	m_exportData.mode = networkTimeHeader.bitfields.mode;

	return true;
}

constexpr boost::static_string<NetworkTimeExport::MAX_IP4_AS_TEXT_LENGTH>
getReferenceIdAsString(std::span<const std::byte, sizeof(uint32_t)> referenceIdPayload, uint8_t stratum) noexcept
{
	constexpr auto refIdPairs = std::to_array({
		std::make_pair("73.78.73.84"sv, "INIT"sv),
		std::make_pair("83.84.69.80"sv, "STEP"sv),
		std::make_pair("68.69.78.89"sv, "DENY"sv),
		std::make_pair("82.65.84.69"sv, "RATE"sv),
	});

	boost::static_string<NetworkTimeExport::MAX_IP4_AS_TEXT_LENGTH> res;
	std::for_each_n(referenceIdPayload.data(), referenceIdPayload.size(),
		[&](const std::byte referenceIdByte) {
			std::format_to(std::back_inserter(
				res), "{}.", static_cast<char>(referenceIdByte));
		});
	res.pop_back();
	
	if (auto it = std::ranges::find_if(refIdPairs, [&](const auto& pair) {
		return pair.first == std::string_view(res.begin(), res.end());
	}); stratum == 0 && it != refIdPairs.end()) {
		res = it->second.data();
	}

	return res;
}

void NetworkTimePlugin::fillTimestamps(std::span<const std::byte> timestampsPayload) noexcept
{
	m_exportData.reference = ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)>
		{timestampsPayload.data(), 2 * sizeof(uint32_t)});

	constexpr std::size_t originOffset = 2 * sizeof(uint32_t);
	m_exportData.origin = ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)>
		{&timestampsPayload[originOffset], 2 * sizeof(uint32_t)});

	constexpr std::size_t receiveOffset = originOffset + 2 * sizeof(uint32_t);
	m_exportData.receive = ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)>
		{&timestampsPayload[receiveOffset], 2 * sizeof(uint32_t)});

	constexpr std::size_t sentOffset = receiveOffset + 2 * sizeof(uint32_t);
	m_exportData.sent = ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)>
		{&timestampsPayload[sentOffset], 2 * sizeof(uint32_t)});
}

void NetworkTimePlugin::makeAllFieldsAvailable(FlowRecord& flowRecord) noexcept
{
	for (auto& [field, handler] : m_fieldHandlers) {
		handler.setAsAvailable(flowRecord);
	}
}

bool NetworkTimePlugin::parseNTP(FlowRecord& flowRecord, std::span<const std::byte> payload, NetworkTimeData& pluginData) noexcept 
{
	constexpr std::size_t NTP_DATA_SIZE = 48;
	if (payload.size() < NTP_DATA_SIZE) {
		return false;
	}

	if (!fillNetworkTimeHeader(static_cast<uint8_t>(payload[0]))) {
		return false;
	}
	
	/// MAYBE TODO GET BACK GLOBAL COUNTERS requests responses total

	constexpr std::size_t stratumOffset = sizeof(NetworkTimeHeader);
	pluginData.stratum = static_cast<uint8_t>(payload[stratumOffset]);
	if (pluginData.stratum > 16) {
		// Error: Bad NTP Stratum or NTP exploit detected.
		return false;
	}
	
	constexpr std::size_t pollOffset = stratumOffset + sizeof(pluginData.stratum);
	pluginData.poll = static_cast<uint8_t>(payload[pollOffset]);
	if (pluginData.poll > 17) {
		// Error: Bad NTP Poll or NTP exploit detected.
		return false;
	}

	constexpr std::size_t precisionOffset = pollOffset + sizeof(pluginData.poll);
	pluginData.precision = static_cast<uint8_t>(payload[precisionOffset]);

	constexpr std::size_t delayOffset = precisionOffset + sizeof(pluginData.precision);
	pluginData.delay = ntohl(*reinterpret_cast<const uint32_t*>(&payload[delayOffset]));

	constexpr std::size_t dispersionOffset = delayOffset + sizeof(pluginData.precision);
	pluginData.dispersion = ntohl(*reinterpret_cast<const uint32_t*>(&payload[dispersionOffset]));

	constexpr std::size_t referenceIdOffset = dispersionOffset + sizeof(pluginData.dispersion);
	pluginData.referenceId = getReferenceIdAsString(std::span<const std::byte, sizeof(uint32_t)>
		{&payload[referenceIdOffset], sizeof(uint32_t)}, pluginData.stratum);
	

	constexpr std::size_t referenceOffset = referenceIdOffset + sizeof(uint32_t);
	fillTimestamps(payload.subspan(referenceOffset));

	makeAllFieldsAvailable(flowRecord);

	return true;
}

void NetworkTimePlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<NetworkTimeData*>(pluginContext));
}


std::string NetworkTimePlugin::getName() const noexcept
{ 
	return ntpPluginManifest.name; 
}

PluginDataMemoryLayout DNSSDPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(NetworkTimeData),
		.alignment = alignof(NetworkTimeData),
	};
}

static const PluginRegistrar<NetworkTimePlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> 
	ntpRegistrar(ntpPluginManifest);

} // namespace ipxp
