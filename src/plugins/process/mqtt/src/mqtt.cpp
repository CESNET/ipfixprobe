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

#include "mqtt.hpp"

#include "mqttGetters.hpp"
#include "mqttOptionsParser.hpp"
#include "mqttTypeFlag.hpp"
#include "variableLengthInt.hpp"

#include <iostream>

#include <arpa/inet.h>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils/spanUtils.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::mqtt {

static const PluginManifest mqttPluginManifest = {
	.name = "mqtt",
	.description = "Mqtt process plugin for parsing mqtt traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			MQTTOptionsParser parser;
			parser.usage(std::cout);
		},
};

/**
 * \brief Read utf8 encoded string as defined in
 * http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html.
 * \param [in] data Pointer to IP payload.
 * \param [in] payload_len IP payload length.
 * \param [in] last_byte Next after last read byte.
 * \return Tuple of read string, its length and bool.
 * Bool is false in case read was unsuccessful.
 */
constexpr static std::optional<std::string_view>
readUTF8String(std::span<const std::byte> payload) noexcept
{
	if (payload.size() < sizeof(uint16_t)) {
		return std::nullopt;
	}

	const uint16_t stringLength = ntohs(*reinterpret_cast<const uint16_t*>(payload.data()));
	if (payload.size() < sizeof(stringLength) + stringLength)
		return std::nullopt;

	return std::make_optional<std::string_view>(
		reinterpret_cast<const char*>(payload.data()),
		static_cast<std::size_t>(stringLength));
}

/**
 * \brief Parse buffer to check if it contains MQTT packets.
 * \param [in] data Pointer to IP payload.
 * \param [in] payload_len IP payload length.
 * \return True if buffer starts with MQTT label as part of connection mqtt packet.
 */
constexpr static bool mqttLabelPresent(std::span<const std::byte> payload) noexcept
{
	if (payload.size() <= sizeof(MQTTTypeFlag))
		return false;

	const std::optional<VariableLengthInt> packetLength
		= readVariableLengthInt(payload.subspan(sizeof(MQTTTypeFlag)));
	if (!packetLength.has_value()) {
		return false;
	}

	const std::size_t labelOffset = sizeof(MQTTTypeFlag) + packetLength->length;
	std::optional<std::string_view> mqttLabel = readUTF8String(payload.subspan(labelOffset));
	return mqttLabel.has_value() && mqttLabel == "MQTT";
}

static FieldGroup
createMQTTSchema(FieldManager& fieldManager, FieldHandlers<MQTTFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("mqtt");

	handlers.insert(
		MQTTFields::MQTT_TYPE_CUMULATIVE,
		schema.addScalarField("MQTT_TYPE_CUMULATIVE", getMQTTTypeCumulativeField));

	handlers.insert(
		MQTTFields::MQTT_VERSION,
		schema.addScalarField("MQTT_VERSION", getMQTTVersionField));

	handlers.insert(
		MQTTFields::MQTT_CONNECTION_FLAGS,
		schema.addScalarField("MQTT_CONNECTION_FLAGS", getMQTTConnectionFlagsField));

	handlers.insert(
		MQTTFields::MQTT_KEEP_ALIVE,
		schema.addScalarField("MQTT_KEEP_ALIVE", getMQTTKeepAliveField));

	handlers.insert(
		MQTTFields::MQTT_CONNECTION_RETURN_CODE,
		schema.addScalarField("MQTT_CONNECTION_RETURN_CODE", getMQTTConnectionReturnCodeField));

	handlers.insert(
		MQTTFields::MQTT_PUBLISH_FLAGS,
		schema.addScalarField("MQTT_PUBLISH_FLAGS", getMQTTPublishFlagsField));

	handlers.insert(
		MQTTFields::MQTT_TOPICS,
		schema.addScalarField("MQTT_TOPICS", getMQTTTopicsField));

	return schema;
}

MQTTPlugin::MQTTPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createMQTTSchema(manager, m_fieldHandlers);
	MQTTOptionsParser parser;
	parser.parse(params.c_str());
	m_maxTopicsToSave = parser.maxTopicsToSave;
}

OnInitResult MQTTPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	std::span<const std::byte> payload = getPayload(*flowContext.packetContext.packet);
	if (mqttLabelPresent(payload)) {
		return OnInitResult::Irrelevant;
	}

	auto& pluginData = *std::construct_at(reinterpret_cast<MQTTContext*>(pluginContext));
	const OnUpdateResult updateRequirement = parseMQTT(payload, flowContext.flowRecord, pluginData);

	if (updateRequirement == OnUpdateResult::Remove) {
		return OnInitResult::PendingConstruction;
	}
	if (updateRequirement == OnUpdateResult::NeedsUpdate) {
		return OnInitResult::ConstructedNeedsUpdate;
	}

	return OnInitResult::ConstructedFinal;
}

/**
 * \brief Parse buffer to check if it contains MQTT packets.
 * \param [in] data Pointer to IP payload.
 * \param [in] payload_len IP payload length.
 * \param [in,out] rec Record to write MQTT data in.
 * \return True if buffer contains set of valid mqtt packets.
 */
OnUpdateResult MQTTPlugin::parseMQTT(
	std::span<const std::byte> payload,
	FlowRecord& flowRecord,
	MQTTContext& mqttContext) noexcept
{
	if (payload.empty()) {
		return OnUpdateResult::Remove;
	}

	uint32_t currentOffset = 0;
	// Each tcp segment may contain more MQTT packets
	while (currentOffset < payload.size()) {
		MQTTTypeFlag typeFlag(static_cast<uint8_t>(payload[currentOffset++]));
		mqttContext.typeCumulative |= (1 << static_cast<uint8_t>(typeFlag.bitfields.type));
		m_fieldHandlers[MQTTFields::MQTT_TYPE_CUMULATIVE].setAsAvailable(flowRecord);

		std::optional<VariableLengthInt> packetLength
			= readVariableLengthInt(payload.subspan(currentOffset));
		if (!packetLength.has_value() || currentOffset + packetLength->value > payload.size()) {
			return OnUpdateResult::Remove;
		}

		currentOffset += packetLength->length;
		const uint16_t firstByteAfterPayload
			= static_cast<uint16_t>(packetLength->value + currentOffset);

		switch (typeFlag.bitfields.type) {
		case MQTTHeaderType::CONNECT: {
			if (!mqttLabelPresent(payload)) {
				return OnUpdateResult::Remove;
			}
			currentOffset += 6; // Skip "MQTT" label(and its 2-byte length)
			mqttContext.version = static_cast<uint8_t>(payload[currentOffset++]);
			m_fieldHandlers[MQTTFields::MQTT_VERSION].setAsAvailable(flowRecord);

			// Only MQTT v3.1.1 and v5.0 are supported
			if (mqttContext.version != 4 && mqttContext.version != 5) {
				return OnUpdateResult::Remove;
			}
			mqttContext.connectionFlags = static_cast<uint8_t>(payload[currentOffset++]);
			m_fieldHandlers[MQTTFields::MQTT_CONNECTION_FLAGS].setAsAvailable(flowRecord);

			mqttContext.keepAlive
				= ntohs(*reinterpret_cast<const uint16_t*>(&payload[currentOffset]));
			m_fieldHandlers[MQTTFields::MQTT_KEEP_ALIVE].setAsAvailable(flowRecord);

			break;
		}
		case MQTTHeaderType::CONNECT_ACK: {
			// Set session present flag
			mqttContext.typeCumulative
				|= static_cast<uint16_t>(static_cast<uint8_t>(payload[currentOffset++]) & 0b1);

			mqttContext.connectionReturnCode = static_cast<uint8_t>(payload[currentOffset++]);
			m_fieldHandlers[MQTTFields::MQTT_CONNECTION_RETURN_CODE].setAsAvailable(flowRecord);

			break;
		}
		case MQTTHeaderType::PUBLISH: {
			mqttContext.publishFlags |= typeFlag.bitfields.flag;
			m_fieldHandlers[MQTTFields::MQTT_PUBLISH_FLAGS].setAsAvailable(flowRecord);

			std::optional<std::string_view> topic = readUTF8String(payload.subspan(currentOffset));
			if (!topic.has_value() || topic->find('#') != std::string_view::npos) {
				return OnUpdateResult::Remove;
			}

			mqttContext.addTopic(*topic, m_maxTopicsToSave);
			m_fieldHandlers[MQTTFields::MQTT_TOPICS].setAsAvailable(flowRecord);

			break;
		}
		case MQTTHeaderType::DISCONNECT: {
			return OnUpdateResult::FlushFlow;
		}
		}

		currentOffset = firstByteAfterPayload; // Skip rest of payload
	}
	return OnUpdateResult::NeedsUpdate;
}

OnUpdateResult MQTTPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	return parseMQTT(
		getPayload(*flowContext.packetContext.packet),
		flowContext.flowRecord,
		*reinterpret_cast<MQTTContext*>(pluginContext));
}

void MQTTPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<MQTTContext*>(pluginContext));
}

PluginDataMemoryLayout MQTTPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(MQTTContext),
		.alignment = alignof(MQTTContext),
	};
}

static const PluginRegistrar<
	MQTTPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	mqttRegistrar(mqttPluginManifest);

} // namespace ipxp::process::mqtt
