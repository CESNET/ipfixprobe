/**
 * @file
 * @brief Plugin for parsing mqtt traffic.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mqtt.hpp"

#include <cstring>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>

#ifdef DEBUG_MQTT
static const bool debug_mqtt = true;
#else
static const bool debug_mqtt = false;
#endif
namespace ipxp {

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

MQTTPlugin::MQTTPlugin(const std::string& params, int pluginID)
	: ProcessPlugin(pluginID)
{
	init(params.c_str());
}

ProcessPlugin::FlowAction MQTTPlugin::post_create(Flow& rec, const Packet& pkt)
{
	if (has_mqtt_protocol_name(reinterpret_cast<const char*>(pkt.payload), pkt.payload_len)) {
		add_ext_mqtt(reinterpret_cast<const char*>(pkt.payload), pkt.payload_len, rec);
		return ProcessPlugin::FlowAction::GET_ALL_DATA;
	}
	return ProcessPlugin::FlowAction::GET_NO_DATA;
}

ProcessPlugin::FlowAction MQTTPlugin::pre_update(Flow& rec, Packet& pkt)
{
	const char* payload = reinterpret_cast<const char*>(pkt.payload);
	RecordExt* ext = rec.get_extension(m_pluginID);
	if (ext == nullptr) {
		return ProcessPlugin::FlowAction::GET_NO_DATA;
	} else {
		parse_mqtt(payload, pkt.payload_len, static_cast<RecordExtMQTT*>(ext));
	}
	return ProcessPlugin::FlowAction::GET_ALL_DATA;
}

/**
 * \brief Read variable integer as defined in
 * http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html. \param [in] data Pointer to IP
 * payload. \param [in] payload_len IP payload length. \param [in] last_byte Next after last read
 * byte. \return Pair of read integer and bool. Bool is false in case read was unsuccessful.
 */
std::pair<uint32_t, bool>
MQTTPlugin::read_variable_int(const char* data, int payload_len, uint32_t& last_byte) const noexcept
{
	uint32_t res = 0;
	bool next;
	for (next = true; next && last_byte < (uint32_t) payload_len; last_byte++) {
		res <<= 8;
		res |= data[last_byte];
		next = (data[last_byte] & 0b1000'0000);
	}
	return last_byte == (uint32_t) payload_len && next ? std::make_pair(0u, false)
													   : std::make_pair(res, true);
}

/**
 * \brief Read utf8 encoded string as defined in
 * http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html. \param [in] data Pointer to IP
 * payload. \param [in] payload_len IP payload length. \param [in] last_byte Next after last read
 * byte. \return Tuple of read string, its length and bool. Bool is false in case read was
 * unsuccessful.
 */
std::tuple<uint32_t, std::string_view, bool>
MQTTPlugin::read_utf8_string(const char* data, int payload_len, uint32_t& last_byte) const noexcept
{
	if (last_byte + 2 >= (uint32_t) payload_len)
		return {0, {}, false};
	uint16_t string_length = ntohs(*(uint16_t*) &data[last_byte]);
	last_byte += 2;
	if (last_byte + string_length >= (uint32_t) payload_len)
		return {0, {}, false};
	return {string_length, std::string_view(&data[last_byte], string_length), true};
}

/**
 * \brief Parse buffer to check if it contains MQTT packets.
 * \param [in] data Pointer to IP payload.
 * \param [in] payload_len IP payload length.
 * \param [in,out] rec Record to write MQTT data in.
 * \return True if buffer contains set of valid mqtt packets.
 */
bool MQTTPlugin::parse_mqtt(const char* data, int payload_len, RecordExtMQTT* rec) noexcept
{
	if (payload_len <= 0)
		return false;
	uint32_t last_byte = 0;
	// Each tcp segment may contain more MQTT packets
	while (last_byte < (uint32_t) payload_len) {
		uint8_t type, flags;
		type = flags = data[last_byte++];
		type >>= 4;
		flags &= 0b00001111;
		rec->type_cumulative |= (0b1 << type);

		auto [remaining_length, success] = read_variable_int(data, payload_len, last_byte);
		if (!success || last_byte + remaining_length > (uint32_t) payload_len) {
			if constexpr (debug_mqtt)
				std::cout << "Invalid remaining length read" << std::endl;
			return false;
		}
		auto first_byte_after_payload = remaining_length + last_byte;
		// Connect packet
		if (type == 1) {
			if (!has_mqtt_protocol_name(data, payload_len)) {
				if constexpr (debug_mqtt)
					std::cout << "Connection packet doesn't have MQTT label" << std::endl;
				return false;
			}
			last_byte += 6; // Skip "MQTT" label(and its 2-byte length)
			rec->version = data[last_byte++];
			// Only MQTT v3.1.1 and v5.0 are supported
			if (rec->version != 4 && rec->version != 5) {
				if constexpr (debug_mqtt)
					std::cout << "Unsupported mqtt version" << std::endl;
				return false;
			}
			rec->connection_flags = data[last_byte++];
			rec->keep_alive = ntohs(*(uint16_t*) &data[last_byte]);
		}
		// Connect ACK packet
		else if (type == 2) {
			rec->session_present_flag = data[last_byte++] & 0b1; /// Connect Acknowledge Flags
			rec->connection_return_code = data[last_byte++];
		}
		// Publish packet
		else if (type == 3) {
			rec->publish_flags |= flags;
			auto [str_len, str, success] = read_utf8_string(data, payload_len, last_byte);
			if (!success) {
				if constexpr (debug_mqtt)
					std::cout << "Invalid utf8 string read" << std::endl;
				return false;
			}
			if (str.find('#') != std::string::npos) {
				if constexpr (debug_mqtt)
					std::cout << "Topic name contains wildcard char" << std::endl;
				return false;
			}
			// Use '#' as delimiter, as '#' and '?' are only forbidden characters for topic name
			if (rec->topics.count++ < maximal_topic_count) {
				rec->topics.str += std::move(std::string(str.begin(), str.end()).append("#"));
			}
		}
		// Disconnect packet
		else if (type == 14) {
			flow_flush = true;
		}

		last_byte = first_byte_after_payload; // Skip rest of payload
	}
	return true;
}

ProcessPlugin::FlowAction MQTTPlugin::post_update([[maybe_unused]] Flow& rec, [[maybe_unused]] const Packet& pkt)
{
	if (flow_flush) {
		flow_flush = false;
		return ProcessPlugin::FlowAction::FLUSH;
	}
	return ProcessPlugin::FlowAction::GET_ALL_DATA;
}

/**
 * \brief Parse buffer to check if it contains MQTT packets.
 * \param [in] data Pointer to IP payload.
 * \param [in] payload_len IP payload length.
 * \return True if buffer starts with MQTT label as part of connection mqtt packet.
 */
bool MQTTPlugin::has_mqtt_protocol_name(const char* data, int payload_len) const noexcept
{
	if (payload_len <= 1)
		return false;
	auto pos = 1u;
	if (auto [_, success] = read_variable_int(data, payload_len, pos); !success)
		return false;
	auto [string_length, str, success] = read_utf8_string(data, payload_len, pos);
	return success && str == "MQTT";
}

void MQTTPlugin::add_ext_mqtt(const char* data, int payload_len, Flow& flow)
{
	if (recPrealloc == nullptr) {
		recPrealloc = new RecordExtMQTT(m_pluginID);
	}
	if (!parse_mqtt(data, payload_len, recPrealloc))
		return;
	flow.add_extension(recPrealloc);
	recPrealloc = nullptr;
}

void MQTTPlugin::init(const char* params)
{
	MQTTOptionsParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}
	maximal_topic_count = parser.m_maximal_topic_count;
}

ProcessPlugin* MQTTPlugin::copy()
{
	return new MQTTPlugin(*this);
}

static const PluginRegistrar<MQTTPlugin, ProcessPluginFactory> mqttRegistrar(mqttPluginManifest);

} // namespace ipxp
