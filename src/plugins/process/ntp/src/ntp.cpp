/**
 * @file
 * @brief Plugin for parsing ntp traffic.
 * @author Alejandro Robledo <robleale@fit.cvut.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses NTP packets and extracts relevant fields,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 * 
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
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
#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

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
		[] (const void* context) { return reinterpret_cast<const NetworkTimeData*>(context)->leap; }
	));

	handlers.insert(NetworkTimeFields::NTP_VERSION, schema.addScalarField(
		"NTP_VERSION",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeData*>(context)->version; }
	));

	handlers.insert(NetworkTimeFields::NTP_MODE, schema.addScalarField(
		"NTP_MODE",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeData*>(context)->mode; }
	));

	handlers.insert(NetworkTimeFields::NTP_STRATUM, schema.addScalarField(
		"NTP_STRATUM",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeData*>(context)->stratum; }
	));

	handlers.insert(NetworkTimeFields::NTP_POLL, schema.addScalarField(
		"NTP_POLL",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeData*>(context)->poll; }
	));

	handlers.insert(NetworkTimeFields::NTP_DELAY, schema.addScalarField(
		"NTP_DELAY",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeData*>(context)->delay; }
	));

	handlers.insert(NetworkTimeFields::NTP_DISPERSION, schema.addScalarField(
		"NTP_DISPERSION",
		[] (const void* context) { return reinterpret_cast<const NetworkTimeData*>(context)->dispersion; }
	));

	handlers.insert(NetworkTimeFields::NTP_REF_ID, schema.addScalarField(
		"NTP_REF_ID",
		[] (const void* context) { return toStringView(reinterpret_cast<const NetworkTimeData*>(context)->referenceId); }
	));

	handlers.insert(NetworkTimeFields::NTP_REF, schema.addScalarField(
		"NTP_REF",
		[] (const void* context) { return toStringView(reinterpret_cast<const NetworkTimeData*>(context)->reference); }
	));

	handlers.insert(NetworkTimeFields::NTP_ORIG, schema.addScalarField(
		"NTP_ORIG",
		[] (const void* context) { return toStringView(reinterpret_cast<const NetworkTimeData*>(context)->origin); }
	));

	handlers.insert(NetworkTimeFields::NTP_RECV, schema.addScalarField(
		"NTP_RECV",
		[] (const void* context) { return toStringView(reinterpret_cast<const NetworkTimeData*>(context)->receive); }
	));

	handlers.insert(NetworkTimeFields::NTP_SENT, schema.addScalarField(
		"NTP_SENT",
		[] (const void* context) { return toStringView(reinterpret_cast<const NetworkTimeData*>(context)->sent); }
	));

	return schema;
}

NetworkTimePlugin::NetworkTimePlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createNetworkTimeSchema(manager, m_fieldHandlers);
}

PluginInitResult NetworkTimePlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr uint16_t NTP_PORT = 123;
	if (flowContext.packet.src_port != NTP_PORT && flowContext.packet.dst_port != NTP_PORT) {
		return {
			.constructionState = ConstructionState::NotConstructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	auto* pluginData = std::construct_at(reinterpret_cast<NetworkTimeData*>(pluginContext));
	if (!parseNTP(flowContext.flowRecord, toSpan<const std::byte>(
		flowContext.packet.payload, flowContext.packet.payload_len), *pluginData)) {
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

static
boost::static_string<NetworkTimeData::MAX_TIMESTAMP_AS_TEXT_LENGTH> 
ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)> timestampSpan)
{
	const double seconds 
		= static_cast<double>(ntohl(*reinterpret_cast<const uint32_t*>(timestampSpan.data())));
	const double fractions = static_cast<double>(ntohl(
		*reinterpret_cast<const uint32_t*>(
			timestampSpan.data() + sizeof(uint32_t)))) * (1.0 / (1ULL << 32));

	boost::static_string<NetworkTimeData::MAX_TIMESTAMP_AS_TEXT_LENGTH> res;
	std::format_to(std::back_inserter(res), "{}", seconds + fractions);
	return res;
}

static 
bool fillNetworkTimeHeader(NetworkTimeHeader networkTimeHeader, NetworkTimeData& pluginData) noexcept
{
	pluginData.leap = networkTimeHeader.bitfields.leap;

	if (networkTimeHeader.bitfields.version != 4) {
		//Error: Bad number of version or NTP exploit detected
		return false;
	}
	pluginData.version = networkTimeHeader.bitfields.version;

	if (networkTimeHeader.bitfields.mode < 3 || 
			networkTimeHeader.bitfields.mode > 4) {
		// Error: Bad NTP mode or NTP exploit detected.
		return false;
	}
	pluginData.mode = networkTimeHeader.bitfields.mode;

	return true;
}

constexpr boost::static_string<NetworkTimeData::MAX_IP4_AS_TEXT_LENGTH>
getReferenceIdAsString(std::span<const std::byte, sizeof(uint32_t)> referenceIdPayload, uint8_t stratum) noexcept
{
	constexpr auto refIdPairs = std::to_array({
		std::make_pair("73.78.73.84"sv, "INIT"sv),
		std::make_pair("83.84.69.80"sv, "STEP"sv),
		std::make_pair("68.69.78.89"sv, "DENY"sv),
		std::make_pair("82.65.84.69"sv, "RATE"sv),
	});

	boost::static_string<NetworkTimeData::MAX_IP4_AS_TEXT_LENGTH> res;
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

static
void fillTimestamps(std::span<const std::byte> timestampsPayload, NetworkTimeData& pluginData) noexcept
{
	pluginData.reference = ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)>
		{timestampsPayload.data(), 2 * sizeof(uint32_t)});

	constexpr std::size_t originOffset = 2 * sizeof(uint32_t);
	pluginData.origin = ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)>
		{&timestampsPayload[originOffset], 2 * sizeof(uint32_t)});

	constexpr std::size_t receiveOffset = originOffset + 2 * sizeof(uint32_t);
	pluginData.receive = ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)>
		{&timestampsPayload[receiveOffset], 2 * sizeof(uint32_t)});

	constexpr std::size_t sentOffset = receiveOffset + 2 * sizeof(uint32_t);
	pluginData.sent = ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)>
		{&timestampsPayload[sentOffset], 2 * sizeof(uint32_t)});
}

void NetworkTimePlugin::makeAllFieldsAvailable(FlowRecord& flowRecord) noexcept
{
	m_fieldHandlers[NetworkTimeFields::NTP_LEAP].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_VERSION].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_MODE].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_STRATUM].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_POLL].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_DELAY].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_DISPERSION].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_REF_ID].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_REF].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_ORIG].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_RECV].setAsAvailable(flowRecord);
	m_fieldHandlers[NetworkTimeFields::NTP_SENT].setAsAvailable(flowRecord);
}

bool NetworkTimePlugin::parseNTP(FlowRecord& flowRecord, std::span<const std::byte> payload, NetworkTimeData& pluginData) noexcept 
{
	constexpr std::size_t NTP_DATA_SIZE = 48;
	if (payload.size() < NTP_DATA_SIZE) {
		return false;
	}

	if (!fillNetworkTimeHeader(static_cast<uint8_t>(payload[0]), pluginData)) {
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
	fillTimestamps(payload.subspan(referenceOffset), pluginData);

	makeAllFieldsAvailable(flowRecord);

	return true;
}

void NetworkTimePlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<NetworkTimeData*>(pluginContext));
}

PluginDataMemoryLayout NetworkTimePlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(NetworkTimeData),
		.alignment = alignof(NetworkTimeData),
	};
}

static const PluginRegistrar<NetworkTimePlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> 
	ntpRegistrar(ntpPluginManifest);

} // namespace ipxp
