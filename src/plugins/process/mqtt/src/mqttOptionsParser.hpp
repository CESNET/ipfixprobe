/**
 * @file mqttOptionsParser.hpp
 * @brief Declaration of MQTTOptionsParser for parsing MQTT plugin options.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <ipfixprobe/options.hpp>

namespace ipxp::process::mqtt {

class MQTTOptionsParser : public OptionsParser {
public:
	uint32_t maxTopicsToSave; ///< Maximal count of topics from Publish packet header to store
							  ///< for each flow

	MQTTOptionsParser()
		: OptionsParser("mqtt", "Parse MQTT traffic")
		, maxTopicsToSave(0)
	{
		register_option(
			"tc",
			"topiccount",
			"count",
			"Export first tc topics from Publish packet header. Topics are separated by #. Default "
			"value is 0.",
			[this](const char* arg) {
				try {
					maxTopicsToSave = std::stoul(arg);
				} catch (...) {
					return false;
				}
				return true;
			},
			OptionFlags::RequiredArgument);
	}
};

} // namespace ipxp