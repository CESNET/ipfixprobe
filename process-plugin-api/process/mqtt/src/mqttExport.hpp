#pragma once

#include <array>
#include <boost/container/static_vector.hpp>
#include <optional>
#include <span>

namespace ipxp
{

struct MQTTExportBase {

	uint16_t typeCumulative; /**< Types of packets presented during communication and session
	present flag. DISCONNECT(1b) | PINGRESP(1b) | PINGREQ(1b) | UNSUBACK(1b) | UNSUBSCRIBE(1b) |
	SUBACK(1b) | SUBSCRIBE(1b) | PUBCOMP(1b) | PUBREL(1b) | PUBREC(1b) | PUBACK(1b) | PUBLISH(1b) |
	CONNACK(1b) | CONNECT(1b) | session present(1b) */
	uint8_t version; ///< Used version of MQTT from last connection packet
	// Connect
	uint8_t connectionFlags; /**< Last connection flags: Username flag(1b) | Password flag(1b)
	| Will retain(1b) | Will QoS(2b) | Clean Session(1b) | 0(1b) */
	uint16_t keepAlive; ///< Last connection keep alive (seconds)
	// CONNACK
	bool sessionPresentFlag; ///< Session present bit from last connack flags. First bit of
							   ///< type_cumulative
	uint8_t connectionReturnCode; ///< Value of last connection return code from CONNACK header
	// PUBLISH
	uint8_t publishFlags; ///< Cumulative of Publish header flags


};  

class MQTTExport : public MQTTExportBase {
public:

	MQTTExport(const uint32_t maxTopicCount)
	: maxTopicCount(maxTopicCount) {}

	bool addTopic(std::string_view topic) noexcept
	{
		if (topics.size() + topic.size() + 1 <= topics.capacity()
			&& topicCount < maxTopicCount) {
			topics.insert(topics.end(), topic.begin(), topic.end());
			// Use '#' as delimiter, as '#' and '?' are only forbidden characters for topic name
			topics.push_back('#');
			topicCount++;
			return true;
    	}
		return false;
	}

	std::string_view getTopics() const noexcept
	{
		return {topics.data(), topics.size()};
	}

private:
	constexpr static std::size_t MAX_TOPICS_LENGTH = 1024;
	uint32_t maxTopicCount;
	boost::container::static_vector<char, MAX_TOPICS_LENGTH> topics;
	uint32_t topicCount = 0;
};

} // namespace ipxp

