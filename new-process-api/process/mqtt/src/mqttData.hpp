#pragma once

#include <array>
#include <boost/container/static_vector.hpp>
#include <optional>
#include <span>

#include <utils/

namespace ipxp
{

class MQTTData : public MQTTExportBase {
public:
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

	constexpr static std::size_t MAX_TOPICS_LENGTH = 1024;
	boost::container::static_vector<char, MAX_TOPICS_LENGTH> topics;

	void addTopic(std::string_view topic, const uint32_t maxTopicsToSave) noexcept
	{
		if (topicCount >= maxTopicsToSave) {
			return;
		}
		pushBackWithDelimiter(topic, topics, '#');
		topicCount++;
	}
	
private:
	uint32_t topicCount = 0;
};

} // namespace ipxp

