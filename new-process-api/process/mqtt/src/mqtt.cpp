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

#include <iostream>
#include <arpa/inet.h>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

#include "variableLengthInt.hpp"
#include "mqttTypeFlag.hpp"

namespace ipxp {

static const PluginManifest mqttPluginManifest = {
	.name = "mqtt",
	.description = "Mqtt process plugin for parsing mqtt traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*MQTTOptionsParser parser;
			parser.usage(std::cout);*/
		},
};

/**
 * \brief Read variable integer as defined in
 * http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html. 
 * \param [in] data Pointer to IP payload. 
 * \param [in] payload_len IP payload length. 
 * \param [in] last_byte Next after last read byte. 
 * \return Pair of read integer and bool. Bool is false in case read was unsuccessful.
 */
constexpr static
std::optional<VariableLenghtInt> readVariableInt(std::span<const std::byte> payload) noexcept
{
	VariableLenghtInt res{0, 0};

	for (const std::byte byte : payload) {
		res.value <<= 8;
		res.value |= static_cast<int32_t>(byte);
		res.readBytes++;
		
		if (const bool readNext = (static_cast<uint32_t>(byte) & 0b1000'0000U); !readNext) {
			return std::make_optional<VariableLenghtInt>(res);
		}
	}

	return std::nullopt;
}

/**
 * \brief Read utf8 encoded string as defined in
 * http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html. 
 * \param [in] data Pointer to IP payload. 
 * \param [in] payload_len IP payload length. 
 * \param [in] last_byte Next after last read byte. 
 * \return Tuple of read string, its length and bool. 
 * Bool is false in case read was unsuccessful.
 */
constexpr static
std::optional<std::string_view>
readUTF8String(std::span<const std::byte> payload) noexcept
{
	if (payload.size() < sizeof(uint16_t)) {
		return std::nullopt;
	}

	const uint16_t stringLength 
		= ntohs(*reinterpret_cast<const uint16_t*>(payload.data()));
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
constexpr static
bool mqttLabelPresent(std::span<const std::byte> payload) noexcept
{
	if (payload.size() <= sizeof(MQTTTypeFlag))
		return false;
	
	const std::optional<VariableLenghtInt> packetLength 
		= readVariableInt(payload.subspan(sizeof(MQTTTypeFlag)));
	if (!packetLength.has_value()) {
		return false;
	}

	const std::size_t labelOffset = sizeof(MQTTTypeFlag) + packetLength->readBytes;
	std::optional<std::string_view> mqttLabel 
		= readUTF8String(payload.subspan(labelOffset));
	return mqttLabel.has_value() && mqttLabel == "MQTT";
}

const inline std::vector<FieldPair<MQTTFields>> fields = {
	{MQTTFields::MQTT_TYPE_CUMULATIVE, "MQTT_TYPE_CUMULATIVE"},
	{MQTTFields::MQTT_VERSION, "MQTT_VERSION"},
	{MQTTFields::MQTT_CONNECTION_FLAGS, "MQTT_CONNECTION_FLAGS"},
	{MQTTFields::MQTT_KEEP_ALIVE, "MQTT_KEEP_ALIVE"},
	{MQTTFields::MQTT_CONNECTION_RETURN_CODE, "MQTT_CONNECTION_RETURN_CODE"},
	{MQTTFields::MQTT_PUBLISH_FLAGS, "MQTT_PUBLISH_FLAGS"},
	{MQTTFields::MQTT_TOPICS, "MQTT_TOPICS"},
};

static FieldSchema createMQTTSchema()
{
	FieldSchema schema("mqtt");

	schema.addScalarField<uint16_t>(
		"MQTT_TYPE_CUMULATIVE",
		FieldDirection::DirectionalIndifferent,
		offsetof(MQTTExportBase, typeCumulative));

	schema.addScalarField<uint8_t>(
		"MQTT_VERSION",
		FieldDirection::DirectionalIndifferent,
		offsetof(MQTTExportBase, version));

	schema.addScalarField<uint8_t>(
		"MQTT_CONNECTION_FLAGS",
		FieldDirection::DirectionalIndifferent,
		offsetof(MQTTExportBase, connectionFlags));

	schema.addScalarField<uint16_t>(
		"MQTT_KEEP_ALIVE",
		FieldDirection::DirectionalIndifferent,
		offsetof(MQTTExportBase, keepAlive));

	schema.addScalarField<uint8_t>(
		"MQTT_CONNECTION_RETURN_CODE",
		FieldDirection::DirectionalIndifferent,
		offsetof(MQTTExportBase, connectionReturnCode));

	schema.addScalarField<uint8_t>(
		"MQTT_PUBLISH_FLAGS",
		FieldDirection::DirectionalIndifferent,
		offsetof(MQTTExportBase, publishFlags));

	/*schema.addVectorField<uint8_t>(
		"MQTT_TOPICS",
		FieldDirection::DirectionalIndifferent,
		[](const void* thisPtr) -> std::span<const uint8_t> {
			return std::span<const uint8_t>(
				reinterpret_cast<const uint8_t*>(
					reinterpret_cast<const MQTTExport*>(thisPtr)->getTopics().data()),
				reinterpret_cast<const MQTTExport*>(thisPtr)->getTopics().size());
		});*/

	return schema;
}

MQTTPlugin::MQTTPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createMQTTSchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	/// TODO OPTION PARSER

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

PluginInitResult MQTTPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	if (mqttLabelPresent(flowContext.packet.payload)) {
		auto* pluginData = std::construct_at(reinterpret_cast<MQTTData*>(pluginContext));
		auto [updateRequirement, flowAction] = parseMQTT(flowContext.packet.payload, flowContext.flowRecord, *pluginData);
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = updateRequirement,
			.flowAction = flowAction,
		};
	}
	return {
		.constructionState = ConstructionState::NotConstructed,
		.updateRequirement = UpdateRequirement::NoUpdateNeeded,
		.flowAction = FlowAction::RemovePlugin,
	};
}

/**
 * \brief Parse buffer to check if it contains MQTT packets.
 * \param [in] data Pointer to IP payload.
 * \param [in] payload_len IP payload length.
 * \param [in,out] rec Record to write MQTT data in.
 * \return True if buffer contains set of valid mqtt packets.
 */
PluginUpdateResult MQTTPlugin::parseMQTT(std::span<const std::byte> payload, FlowRecord& flowRecord, MQTTData& mqttData) noexcept
{
	if (payload.empty()) {
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::RemovePlugin,
		};
	}

	uint32_t currentOffset = 0;
	// Each tcp segment may contain more MQTT packets
	while (currentOffset < payload.size()) {
		MQTTTypeFlag typeFlag(static_cast<uint8_t>(payload[currentOffset++]));
		mqttData.typeCumulative 
			|= (1 << static_cast<uint8_t>(typeFlag.bitfields.type));
		m_fieldHandlers[MQTTFields::MQTT_TYPE_CUMULATIVE].setAsAvailable(flowRecord);

		std::optional<VariableLenghtInt> packetLength 
			= readVariableInt(payload.subspan(currentOffset));
		if (!packetLength.has_value() || 
				currentOffset + packetLength->value > payload.size()) {
			return {
				.updateRequirement = UpdateRequirement::NoUpdateNeeded,
				.flowAction = FlowAction::RemovePlugin,
			};
		}

		currentOffset += packetLength->readBytes;
		const uint16_t firstByteAfterPayload 
			= static_cast<uint16_t>(packetLength->value + currentOffset);
		
		switch(typeFlag.bitfields.type) {
		case MQTTHeaderType::CONNECT: {
			if (!mqttLabelPresent(payload)) {
				return {
					.updateRequirement = UpdateRequirement::NoUpdateNeeded,
					.flowAction = FlowAction::RemovePlugin,
				};
			}
			currentOffset += 6; // Skip "MQTT" label(and its 2-byte length)
			mqttData.version = static_cast<uint8_t>(payload[currentOffset++]);
			m_fieldHandlers[MQTTFields::MQTT_VERSION].setAsAvailable(flowRecord);

			// Only MQTT v3.1.1 and v5.0 are supported
			if (mqttData.version != 4 && mqttData.version != 5) {
				return {
					.updateRequirement = UpdateRequirement::NoUpdateNeeded,
					.flowAction = FlowAction::RemovePlugin,
				};
			}
			mqttData.connectionFlags = static_cast<uint8_t>(payload[currentOffset++]);
			m_fieldHandlers[MQTTFields::MQTT_CONNECTION_FLAGS].setAsAvailable(flowRecord);
			
			mqttData.keepAlive 
				= ntohs(*reinterpret_cast<const uint16_t*>(&payload[currentOffset]));
			m_fieldHandlers[MQTTFields::MQTT_KEEP_ALIVE].setAsAvailable(flowRecord);
			
			break;
		}
		case MQTTHeaderType::CONNECT_ACK: {
			// Set session present flag
			mqttData.typeCumulative 
				|= static_cast<uint16_t>(
					static_cast<uint8_t>(payload[currentOffset++]) & 0b1);
			
			mqttData.connectionReturnCode = static_cast<uint8_t>(payload[currentOffset++]);
			m_fieldHandlers[MQTTFields::MQTT_CONNECTION_RETURN_CODE].setAsAvailable(flowRecord);
			
			break;
		}
		case MQTTHeaderType::PUBLISH: {
			mqttData.publishFlags |= typeFlag.bitfields.flag;
			m_fieldHandlers[MQTTFields::MQTT_PUBLISH_FLAGS].setAsAvailable(flowRecord);
			
			std::optional<std::string_view> topic = readUTF8String(payload.subspan(currentOffset));
			if (!topic.has_value() || topic->find('#') != std::string_view::npos) {
				return {
					.updateRequirement = UpdateRequirement::NoUpdateNeeded,
					.flowAction = FlowAction::RemovePlugin,
				};
			}

			mqttData.addTopic(*topic, maxTopicsToSave);
			m_fieldHandlers[MQTTFields::MQTT_TOPICS].setAsAvailable(flowRecord);
			
			break;
		}
		case MQTTHeaderType::DISCONNECT: {
			return {
				.updateRequirement = UpdateRequirement::NoUpdateNeeded,
				.flowAction = FlowAction::Flush,
			};
		}
		}

		currentOffset = firstByteAfterPayload; // Skip rest of payload
	}
	return {
		.updateRequirement = UpdateRequirement::RequiresUpdate,
		.flowAction = FlowAction::NoAction,
	};
}

void MQTTPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<MQTTData*>(pluginContext));
}

PluginUpdateResult MQTTPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	return parseMQTT(flowContext.packet.payload, flowContext.flowRecord, *reinterpret_cast<MQTTData*>(pluginContext));
}

std::string MQTTPlugin::getName() const noexcept
{ 
	return mqttPluginManifest.name; 
}

static const PluginRegistrar<MQTTPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>> 
	mqttRegistrar(mqttPluginManifest);

} // namespace ipxp
