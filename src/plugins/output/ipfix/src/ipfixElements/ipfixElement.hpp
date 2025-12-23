#pragma once

#include <cstdint>
#include <string>

#include <yaml-cpp/yaml.h>

struct IPFIXElement {
	constexpr static int16_t VARIABLE_LENGTH = 1;

	constexpr IPFIXElement(const YAML::Node& field)
	{
		if (!field.IsMap()) {
			throw std::runtime_error(
				"Invalid IPFIX exporter elements configuration file "
				"format. Field node must be a map.");
		}
		if (!field["name"].IsDefined() || !field["pen"].IsDefined() || !field["id"].IsDefined()
			|| !field["length"].IsDefined() || field.size() != 4) {
			throw std::runtime_error(
				"Invalid IPFIX exporter elements configuration file "
				"format. Field node must contain 'name', 'pen', 'id' and "
				"'length' attributes.");
		}

		name = field["name"].as<std::string>();
		pen = field["pen"].as<uint32_t>();
		id = field["id"].as<uint16_t>();
		length = field["length"].as<int16_t>();
		if (length != VARIABLE_LENGTH && length <= 0) {
			throw std::runtime_error(
				"Invalid IPFIX exporter elements configuration file "
				"format. 'length' attribute must be positive integer or -1.");
		}
	}

	std::string name;
	uint16_t id;
	int16_t length;
	uint32_t pen;
};