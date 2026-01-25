/**
 * @file ipfixExporterElementsParser.hpp
 * @brief IPFIX exporter elements file parser.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */
#pragma once

#include "../utils/heterogeneousStringHash.hpp"
#include "ipfixElement.hpp"

#include <fstream>

#include <yaml-cpp/yaml.h>

namespace ipxp::output::ipfix {

/**
 * @class IPFIXExporterElementsParser
 * @brief Class for parsing IPFIX exporter elements into elements map.
 */
class IPFIXExporterElementsParser {
public:
	/**
	 * @brief Constructs an IPFIXExporterElementsParser and parses the elements from the given file.
	 * @param configPath Path to the IPFIX exporter elements configuration file.
	 * @throws std::runtime_error if the file format is invalid or if there are duplicate protocols.
	 */
	IPFIXExporterElementsParser(std::string_view configPath)
	{
		const YAML::Node root = YAML::LoadFile(configPath.data());
		if (!root.IsMap()) {
			throw std::runtime_error(
				"Invalid IPFIX exporter elements configuration file format. Root node must be a "
				"map.");
		}

		for (const auto& it : root) {
			const auto& protocol = it.first.as<std::string>();
			const auto& fields = it.second;

			if (!fields.IsSequence()) {
				throw std::runtime_error(
					"Invalid IPFIX exporter elements configuration file format. Fields node must "
					"be "
					"a sequence.");
			}

			auto protocolElements = fields | std::views::transform([](const YAML::Node& field) {
										const IPFIXElement element(field);
										return std::pair(element.name, element);
									})
				| std::ranges::to<typename ElementsMap::mapped_type>();

			if (m_ipfixElements.contains(protocol)) {
				throw std::runtime_error(
					"Duplicate protocol '" + protocol
					+ "' found in IPFIX exporter elements configuration file.");
			}
			m_ipfixElements[protocol] = std::move(protocolElements);
		}
	}

	/**
	 * @brief Retrieves the parsed elements map.
	 * @return The elements map.
	 */
	// const ElementsMap& getElementsMap() const { return m_ipfixElements; }

	bool hasElement(std::string_view protocol, std::string_view elementName) const
	{
		if (!m_ipfixElements.contains(protocol)) {
			return false;
		}

		return m_ipfixElements.at(protocol).contains(elementName);
	}

	const IPFIXElement& getElement(std::string_view protocol, std::string_view elementName) const
	{
		return m_ipfixElements.at(protocol).at(elementName);
	}

private:
	using ElementsMap = std::unordered_map<
		std::string,
		std::unordered_map<
			std::string,
			IPFIXElement,
			utils::HeterogeneousStringHash,
			std::equal_to<>>,
		utils::HeterogeneousStringHash,
		std::equal_to<>>;

	ElementsMap m_ipfixElements;
};

} // namespace ipxp::output::ipfix