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

//const char OTHER[] = "OTHER"; /*OTHER Value of NTP reference ID*/

const inline std::vector<FieldPair<NetworkTimeFields>> fields = {
	{NetworkTimeFields::NTP_LEAP, "NTP_LEAP"},
	{NetworkTimeFields::NTP_VERSION, "NTP_VERSION"},
	{NetworkTimeFields::NTP_MODE, "NTP_MODE"},
	{NetworkTimeFields::NTP_STRATUM, "NTP_STRATUM"},
	{NetworkTimeFields::NTP_POLL, "NTP_POLL"},
	{NetworkTimeFields::NTP_DELAY, "NTP_DELAY"},
	{NetworkTimeFields::NTP_DISPERSION, "NTP_DISPERSION"},
	{NetworkTimeFields::NTP_REF_ID, "NTP_REF_ID"},
	{NetworkTimeFields::NTP_REF, "NTP_REF"},
	{NetworkTimeFields::NTP_ORIG, "NTP_ORIG"},
	{NetworkTimeFields::NTP_RECV, "NTP_RECV"},
	{NetworkTimeFields::NTP_SENT, "NTP_SENT"},
};

static FieldSchema createNetworkTimeSchema()
{
	FieldSchema schema("ntp");

	schema.addScalarField<uint8_t>(
		"NTP_LEAP",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, leap));

	schema.addScalarField<uint8_t>(
		"NTP_VERSION",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, version));

	schema.addScalarField<uint8_t>(
		"NTP_MODE",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, mode));

	schema.addScalarField<uint8_t>(
		"NTP_STRATUM",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, stratum));

	schema.addScalarField<uint8_t>(
		"NTP_POLL",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, poll));

	schema.addScalarField<uint32_t>(
		"NTP_DELAY",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, delay));

	schema.addScalarField<uint32_t>(
		"NTP_DISPERSION",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, dispersion));

	// TODO FIX STIRNG EXPORT
	/*schema.addScalarField<uint8_t>(
		"NTP_REF_ID",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, version));

	schema.addScalarField<uint8_t>(
		"NTP_REF",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, version));

	schema.addScalarField<uint8_t>(
		"NTP_ORIG",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, version));

	schema.addScalarField<uint8_t>(
		"NTP_RECV",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, version));

	schema.addScalarField<uint8_t>(
		"NTP_SENT",
		FieldDirection::DirectionalIndifferent,
		offsetof(NetworkTimeExport, version));*/

	return schema;
}

NetworkTimePlugin::NetworkTimePlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createNetworkTimeSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction NetworkTimePlugin::onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
{
	if (packet.flowKey.srcPort == 123 || packet.flowKey.dstPort == 123) {
		return parseNTP(flowRecord, packet.payload);
	}
	return FlowAction::RequestNoData;
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

void NetworkTimePlugin::makeAllFieldsAvailable(FlowRecord& flowRecord) noexcept
{
	for (const auto& [field, _] : fields) {
		m_fieldHandlers[field].setAsAvailable(flowRecord);
	}
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

FlowAction NetworkTimePlugin::parseNTP(FlowRecord& flowRecord, std::span<const std::byte> payload) noexcept 
{
	constexpr std::size_t NTP_DATA_SIZE = 48;
	if (payload.size() < NTP_DATA_SIZE) {
		return FlowAction::RequestNoData;
	}

	if (!fillNetworkTimeHeader(static_cast<uint8_t>(payload[0]))) {
		return FlowAction::RequestNoData;
	}
	
	/// MAYBE TODO GET BACK GLOBAL COUNTERS requests responses total

	constexpr std::size_t stratumOffset = sizeof(NetworkTimeHeader);
	m_exportData.stratum = static_cast<uint8_t>(payload[stratumOffset]);
	if (m_exportData.stratum > 16) {
		// Error: Bad NTP Stratum or NTP exploit detected.
		return FlowAction::RequestNoData;
	}
	
	constexpr std::size_t pollOffset = stratumOffset + sizeof(m_exportData.stratum);
	m_exportData.poll = static_cast<uint8_t>(payload[pollOffset]);
	if (m_exportData.poll > 17) {
		// Error: Bad NTP Poll or NTP exploit detected.
		return FlowAction::RequestNoData;
	}	

	constexpr std::size_t precisionOffset = pollOffset + sizeof(m_exportData.poll);
	m_exportData.precision = static_cast<uint8_t>(payload[precisionOffset]);

	constexpr std::size_t delayOffset = precisionOffset + sizeof(m_exportData.precision);
	m_exportData.delay = ntohl(*reinterpret_cast<const uint32_t*>(&payload[delayOffset]));

	constexpr std::size_t dispersionOffset = delayOffset + sizeof(m_exportData.precision);
	m_exportData.dispersion = ntohl(*reinterpret_cast<const uint32_t*>(&payload[dispersionOffset]));


	constexpr std::size_t referenceIdOffset = dispersionOffset + sizeof(m_exportData.dispersion);
	m_exportData.referenceId = getReferenceIdAsString(std::span<const std::byte, sizeof(uint32_t)>
		{&payload[referenceIdOffset], sizeof(uint32_t)}, m_exportData.stratum);
	

	constexpr std::size_t referenceOffset = referenceIdOffset + sizeof(uint32_t);
	fillTimestamps(payload.subspan(referenceOffset));

	makeAllFieldsAvailable(flowRecord);

	return FlowAction::Flush;
}

ProcessPlugin* NetworkTimePlugin::clone(std::byte* constructAtAddress) const
{
	return std::construct_at(reinterpret_cast<NetworkTimePlugin*>(constructAtAddress), *this);
}

std::string NetworkTimePlugin::getName() const { 
	return ntpPluginManifest.name; 
}

const void* NetworkTimePlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<NetworkTimePlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> 
	ntpRegistrar(ntpPluginManifest);

} // namespace ipxp
