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

#include "ntpGetters.hpp"

#include <format>
#include <iostream>

#include <arpa/inet.h>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::ntp {

using namespace std::string_view_literals;

static const PluginManifest ntpPluginManifest = {
	.name = "ntp",
	.description = "Ntp process plugin for parsing ntp traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("ntp", "Parse NTP traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createNetworkTimeSchema(FieldManager& fieldManager, FieldHandlers<NetworkTimeFields>& handlers)
{
	FieldGroup schema = fieldManager.createFieldGroup("ntp");

	handlers.insert(
		NetworkTimeFields::NTP_LEAP,
		schema.addScalarField("NTP_LEAP", getNTPLeapField));

	handlers.insert(
		NetworkTimeFields::NTP_VERSION,
		schema.addScalarField("NTP_VERSION", getNTPVersionField));

	handlers.insert(
		NetworkTimeFields::NTP_MODE,
		schema.addScalarField("NTP_MODE", getNTPModeField));

	handlers.insert(
		NetworkTimeFields::NTP_STRATUM,
		schema.addScalarField("NTP_STRATUM", getNTPStratumField));

	handlers.insert(
		NetworkTimeFields::NTP_POLL,
		schema.addScalarField("NTP_POLL", getNTPPollField));

	handlers.insert(
		NetworkTimeFields::NTP_DELAY,
		schema.addScalarField("NTP_DELAY", getNTPDelayField));

	handlers.insert(
		NetworkTimeFields::NTP_DISPERSION,
		schema.addScalarField("NTP_DISPERSION", getNTPDispersionField));

	handlers.insert(
		NetworkTimeFields::NTP_REF_ID,
		schema.addScalarField("NTP_REF_ID", getNTPRefIdField));

	handlers.insert(NetworkTimeFields::NTP_REF, schema.addScalarField("NTP_REF", getNTPRefField));

	handlers.insert(
		NetworkTimeFields::NTP_ORIG,
		schema.addScalarField("NTP_ORIG", getNTPOrigField));

	handlers.insert(
		NetworkTimeFields::NTP_RECV,
		schema.addScalarField("NTP_RECV", getNTPRecvField));

	handlers.insert(
		NetworkTimeFields::NTP_SENT,
		schema.addScalarField("NTP_SENT", getNTPSentField));

	return schema;
}

NetworkTimePlugin::NetworkTimePlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& manager)
{
	createNetworkTimeSchema(manager, m_fieldHandlers);
}

OnInitResult NetworkTimePlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	constexpr uint16_t NTP_PORT = 123;
	if (flowContext.flowRecord.flowKey.srcPort != NTP_PORT
		&& flowContext.flowRecord.flowKey.dstPort != NTP_PORT) {
		return OnInitResult::Irrelevant;
	}

	auto& ntpContext = *std::construct_at(reinterpret_cast<NetworkTimeContext*>(pluginContext));
	if (!parseNTP(
			flowContext.flowRecord,
			getPayload(*flowContext.packetContext.packet),
			ntpContext)) {
		return OnInitResult::ConstructedFinal;
	}

	return OnInitResult::ConstructedFinal;
}

static boost::static_string<NetworkTimeContext::MAX_TIMESTAMP_AS_TEXT_LENGTH>
ntpTimestampToString(std::span<const std::byte, 2 * sizeof(uint32_t)> timestampSpan)
{
	const double seconds
		= static_cast<double>(ntohl(*reinterpret_cast<const uint32_t*>(timestampSpan.data())));
	const double fractions
		= static_cast<double>(
			  ntohl(*reinterpret_cast<const uint32_t*>(timestampSpan.data() + sizeof(uint32_t))))
		* (1.0 / (1ULL << 32));

	boost::static_string<NetworkTimeContext::MAX_TIMESTAMP_AS_TEXT_LENGTH> res;
	std::format_to(std::back_inserter(res), "{}", seconds + fractions);
	return res;
}

static bool
fillNetworkTimeHeader(NetworkTimeHeader networkTimeHeader, NetworkTimeContext& ntpContext) noexcept
{
	ntpContext.leap = networkTimeHeader.bitfields.leap;

	if (networkTimeHeader.bitfields.version != 4) {
		// Error: Bad number of version or NTP exploit detected
		return false;
	}
	ntpContext.version = networkTimeHeader.bitfields.version;

	if (networkTimeHeader.bitfields.mode < 3 || networkTimeHeader.bitfields.mode > 4) {
		// Error: Bad NTP mode or NTP exploit detected.
		return false;
	}
	ntpContext.mode = networkTimeHeader.bitfields.mode;

	return true;
}

constexpr boost::static_string<NetworkTimeContext::MAX_IP4_AS_TEXT_LENGTH> getReferenceIdAsString(
	std::span<const std::byte, sizeof(uint32_t)> referenceIdPayload,
	uint8_t stratum) noexcept
{
	constexpr auto refIdPairs = std::to_array({
		std::make_pair("73.78.73.84"sv, "INIT"sv),
		std::make_pair("83.84.69.80"sv, "STEP"sv),
		std::make_pair("68.69.78.89"sv, "DENY"sv),
		std::make_pair("82.65.84.69"sv, "RATE"sv),
	});

	boost::static_string<NetworkTimeContext::MAX_IP4_AS_TEXT_LENGTH> res;
	std::for_each_n(
		referenceIdPayload.data(),
		referenceIdPayload.size(),
		[&](const std::byte referenceIdByte) {
			std::format_to(std::back_inserter(res), "{}.", static_cast<char>(referenceIdByte));
		});
	res.pop_back();

	if (auto it = std::ranges::find_if(
			refIdPairs,
			[&](const auto& pair) {
				return pair.first == std::string_view(res.begin(), res.end());
			});
		stratum == 0 && it != refIdPairs.end()) {
		res = it->second.data();
	}

	return res;
}

static void fillTimestamps(
	std::span<const std::byte> timestampsPayload,
	NetworkTimeContext& ntpContext) noexcept
{
	ntpContext.reference = ntpTimestampToString(
		std::span<const std::byte, 2 * sizeof(uint32_t)> {
			timestampsPayload.data(),
			2 * sizeof(uint32_t)});

	constexpr std::size_t originOffset = 2 * sizeof(uint32_t);
	ntpContext.origin = ntpTimestampToString(
		std::span<const std::byte, 2 * sizeof(uint32_t)> {
			&timestampsPayload[originOffset],
			2 * sizeof(uint32_t)});

	constexpr std::size_t receiveOffset = originOffset + 2 * sizeof(uint32_t);
	ntpContext.receive = ntpTimestampToString(
		std::span<const std::byte, 2 * sizeof(uint32_t)> {
			&timestampsPayload[receiveOffset],
			2 * sizeof(uint32_t)});

	constexpr std::size_t sentOffset = receiveOffset + 2 * sizeof(uint32_t);
	ntpContext.sent = ntpTimestampToString(
		std::span<const std::byte, 2 * sizeof(uint32_t)> {
			&timestampsPayload[sentOffset],
			2 * sizeof(uint32_t)});
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

bool NetworkTimePlugin::parseNTP(
	FlowRecord& flowRecord,
	std::span<const std::byte> payload,
	NetworkTimeContext& ntpContext) noexcept
{
	constexpr std::size_t NTP_DATA_SIZE = 48;
	if (payload.size() < NTP_DATA_SIZE) {
		return false;
	}

	if (!fillNetworkTimeHeader(static_cast<uint8_t>(payload[0]), ntpContext)) {
		return false;
	}

	constexpr std::size_t stratumOffset = sizeof(NetworkTimeHeader);
	ntpContext.stratum = static_cast<uint8_t>(payload[stratumOffset]);
	if (ntpContext.stratum > 16) {
		// Error: Bad NTP Stratum or NTP exploit detected.
		return false;
	}

	constexpr std::size_t pollOffset = stratumOffset + sizeof(ntpContext.stratum);
	ntpContext.poll = static_cast<uint8_t>(payload[pollOffset]);
	if (ntpContext.poll > 17) {
		// Error: Bad NTP Poll or NTP exploit detected.
		return false;
	}

	constexpr std::size_t precisionOffset = pollOffset + sizeof(ntpContext.poll);
	ntpContext.precision = static_cast<uint8_t>(payload[precisionOffset]);

	constexpr std::size_t delayOffset = precisionOffset + sizeof(ntpContext.precision);
	ntpContext.delay = ntohl(*reinterpret_cast<const uint32_t*>(&payload[delayOffset]));

	constexpr std::size_t dispersionOffset = delayOffset + sizeof(ntpContext.precision);
	ntpContext.dispersion = ntohl(*reinterpret_cast<const uint32_t*>(&payload[dispersionOffset]));

	constexpr std::size_t referenceIdOffset = dispersionOffset + sizeof(ntpContext.dispersion);
	ntpContext.referenceId = getReferenceIdAsString(
		std::span<const std::byte, sizeof(uint32_t)> {
			&payload[referenceIdOffset],
			sizeof(uint32_t)},
		ntpContext.stratum);

	constexpr std::size_t referenceOffset = referenceIdOffset + sizeof(uint32_t);
	fillTimestamps(payload.subspan(referenceOffset), ntpContext);

	makeAllFieldsAvailable(flowRecord);

	return true;
}

void NetworkTimePlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<NetworkTimeContext*>(pluginContext));
}

PluginDataMemoryLayout NetworkTimePlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(NetworkTimeContext),
		.alignment = alignof(NetworkTimeContext),
	};
}

static const PluginRegistrar<
	NetworkTimePlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	ntpRegistrar(ntpPluginManifest);

} // namespace ipxp::process::ntp
