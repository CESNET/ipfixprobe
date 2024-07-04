/**
* \file mqtt.hpp
* \brief MQTT plugin for ipfixprobe
* \author Damir Zainullin <zaidamilda@gmail.com>
* \date 2024
*/
/*
* Copyright (C) 2023 CESNET
*
* LICENSE TERMS
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in
*    the documentation and/or other materials provided with the
*    distribution.
* 3. Neither the name of the Company nor the names of its contributors
*    may be used to endorse or promote products derived from this
*    software without specific prior written permission.
*/
#ifndef CACHE_CPP_TPLUGIN_HPP
#define CACHE_CPP_TPLUGIN_HPP


#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/utils.hpp>
#include <numeric>
#include <cstring>
#include "sstream"

namespace ipxp {

#define MQTT_UNIREC_TEMPLATE "MQTT_TYPE_CUMULATIVE, MQTT_VERSION, MQTT_CONNECTION_FLAGS, MQTT_KEEP_ALIVE, MQTT_CONNECTION_RETURN_CODE, MQTT_PUBLISH_FLAGS, MQTT_TOPICS"

UR_FIELDS (
    uint16 MQTT_TYPE_CUMULATIVE,
    uint8 MQTT_VERSION,
    uint8 MQTT_CONNECTION_FLAGS,
    uint16 MQTT_KEEP_ALIVE,
    uint8 MQTT_CONNECTION_RETURN_CODE,
    uint8 MQTT_PUBLISH_FLAGS,
    string MQTT_TOPICS
)

class MQTTOptionsParser : public OptionsParser
{
public:
    uint32_t m_maximal_topic_count; ///< Maximal count of topics from Publish packet header to store for each flow

    MQTTOptionsParser() : OptionsParser("mqtt", "Parse MQTT traffic"), m_maximal_topic_count(0)
    {
        register_option(
            "tc",
            "topiccount",
            "count",
            "Export first tc topics from Publish packet header. Topics are separated by #. Default value is 0.",
            [this](const char *arg){try {
                    m_maximal_topic_count = str2num<decltype(m_maximal_topic_count)>(arg);
                } catch(std::invalid_argument &e) {
                    return false;
                }
                return true;
            },
            OptionFlags::RequiredArgument);
    }
};

struct RecordExtMQTT : public RecordExt {
    static int REGISTERED_ID;
    RecordExtMQTT() :
        RecordExt(REGISTERED_ID),
        type_cumulative(0),
        version(0),
        connection_flags(0),
        keep_alive(0),
        session_present_flag(false),
        connection_return_code(0),
        publish_flags(0) {}

    uint16_t type_cumulative; ///< Types of packets presented during communication and session present flag. DISCONNECT(1b) | PINGRESP(1b) | PINGREQ(1b) | UNSUBACK(1b) | UNSUBSCRIBE(1b) | SUBACK(1b) | SUBSCRIBE(1b) | PUBCOMP(1b) | PUBREL(1b) | PUBREC(1b) | PUBACK(1b) | PUBLISH(1b) | CONNACK(1b) | CONNECT(1b) | session present(1b)
    uint8_t version; ///< Used version of MQTT from last connection packet
    //Connect
    uint8_t connection_flags; ///< Last connection flags: Username flag(1b) | Password flag(1b) | Will retain(1b) | Will QoS(2b) | Clean Session(1b) | 0(1b)
    uint16_t keep_alive; ///< Last connection keep alive (seconds)
    //CONNACK
    bool session_present_flag; ///< Session present bit from last connack flags. First bit of type_cumulative
    uint8_t connection_return_code; ///< Value of last connection return code from CONNACK header
    //PUBLISH
    uint8_t publish_flags; ///< Cumulative of Publish header flags
    struct {
        std::string str;
        uint32_t count = 0;
    } topics; ///< Struct to keep all recorded and concatenated topics from Publish header and its count

    virtual int fill_ipfix(uint8_t *buffer, int size)
    {
        auto max_length = 8u + topics.str.size() + 3u;
        if ((uint32_t)size < max_length)
            return -1;
        *(uint16_t*) (buffer) = ntohs(type_cumulative | session_present_flag);
        *(buffer + 2) = version;
        *(buffer + 3) = connection_flags;
        *(uint16_t*) (buffer + 4) = ntohs(keep_alive);
        *(buffer + 6) = connection_return_code;
        *(buffer + 7) = publish_flags;
        auto total_length = 8u;
        total_length += variable2ipfix_buffer(buffer + total_length,(uint8_t*) topics.str.c_str(), topics.str.size());
        return total_length;
    }

    const char **get_ipfix_tmplt() const
    {
        static const char *ipfix_template[] = {
            IPFIX_MQTT_TEMPLATE(IPFIX_FIELD_NAMES)
            nullptr
        };
        return ipfix_template;
    }
#ifdef WITH_NEMEA
    void fill_unirec(ur_template_t *tmplt, void *record) override
    {
        ur_set(tmplt, record, F_MQTT_TYPE_CUMULATIVE, type_cumulative | session_present_flag);
        ur_set(tmplt, record, F_MQTT_VERSION, version);
        ur_set(tmplt, record, F_MQTT_CONNECTION_FLAGS, connection_flags);
        ur_set(tmplt, record, F_MQTT_KEEP_ALIVE, keep_alive);
        ur_set(tmplt, record, F_MQTT_CONNECTION_RETURN_CODE, connection_return_code);
        ur_set(tmplt, record, F_MQTT_PUBLISH_FLAGS, publish_flags);
        ur_set_string(tmplt, record, F_MQTT_TOPICS, topics.str.c_str());
    }

    const char *get_unirec_tmplt() const
    {
        return MQTT_UNIREC_TEMPLATE;
    }
#endif
    std::string get_text() const override
    {
        std::ostringstream out;
        out << "type_cumulative=" << type_cumulative
            << ",version=" << std::to_string(version)
            << ",connection_flags=" << std::to_string(connection_flags)
            << ",keep_alive=" << keep_alive
            << ",connection_return_code=" << std::to_string(connection_return_code)
            << ",publish_flags=" << std::to_string(publish_flags)
            << ",topics=\"" << topics.str << "\"";
        return out.str();
    }
};



class MQTTPlugin : public ProcessPlugin
{
public:
    int post_create(Flow &rec, const Packet &pkt) override;
    int pre_update(Flow &rec, Packet &pkt) override;
    void pre_export(Flow &rec) override;
    int post_update(Flow &rec, const Packet &pkt) override;
    RecordExt *get_ext() const { return new RecordExtMQTT(); }
    OptionsParser *get_parser() const { return new MQTTOptionsParser(); }
    std::string get_name() const { return "mqtt"; }
    ProcessPlugin *copy();
    void init(const char *params) override;
private:
    bool flow_flush = false; ///< Tell storage plugin to flush current Flow.
    uint32_t maximal_topic_count = 0; ///< Maximal count of topics from Publish packet header to store for each flow
    RecordExtMQTT *recPrealloc; ///< Preallocated extension.
    bool parse_mqtt(const char* data, int payload_len, RecordExtMQTT* rec) noexcept;
    void add_ext_mqtt(const char *data, int payload_len, Flow &flow);
    std::pair<uint32_t, bool> read_variable_int(const char* data, int payload_len, uint32_t& last_byte)const noexcept;
    std::tuple<uint32_t, std::string_view, bool> read_utf8_string(const char* data, int payload_len, uint32_t& last_byte) const noexcept;
    bool has_mqtt_protocol_name(const char* data, int payload_len) const noexcept;

};

} // namespace ipxp

#endif // CACHE_CPP_TPLUGIN_HPP
