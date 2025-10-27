/**
 * @file
 * @brief JSON parser to obtain flow data from osquery declaration.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <optional>
#include <string>

namespace ipxp::process::osquery {

/**
 * @class JsonParser
 * @brief Parses OS query data to fill the `AboutProgram` and `AboutOSVersion`.
 */
class JsonParser {
public:
	struct AboutProgram {
		std::string name;
		std::string username;
	};

	struct AboutOSVersion {
		std::string arch;
		std::string build;
		std::string hostname;
		std::string majorNumber;
		std::string minorNumber;
		std::string name;
		std::string platform;
		std::string platformLike;
		std::string version;
	};

	/**
	 * @brief Parses `AboutOSVersion`.
	 *
	 * @param jsonData JSON input.
	 * @return Parsed `AboutOSVersion` or `std::nullopt` if parsing failed.
	 */
	static std::optional<AboutOSVersion> parseJsonOSVersion(std::string_view jsonData) noexcept;

	/**
	 * @brief Parses `AboutProgram`.
	 *
	 * @param jsonData JSON input.
	 * @return Parsed `AboutProgram` or `std::nullopt` if parsing failed.
	 */
	static std::optional<AboutProgram> parseJsonAboutProgram(std::string_view jsonData) noexcept;

	/**
	 * @brief Searches for given key in JSON data.
	 *
	 * @param jsonData JSON input.
	 * @param key Key to search for.
	 * @return Parsed value or `std::nullopt` if not found.
	 */
	static std::optional<std::string_view>
	findValueByKey(std::string_view jsonData, std::string_view key);
};

} // namespace ipxp::process::osquery
