/**
 * @file
 * @brief JSON parser to obtain flow data from osquery implementation.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "jsonParser.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <ranges>
#include <stdexcept>

#include <boost/iterator/function_input_iterator.hpp>

namespace ipxp::process::osquery {

using namespace std::literals::string_view_literals;

enum class ParsingStatus { SUCCESS, FAILURE, NO_DATA };

constexpr static std::pair<std::string_view, ParsingStatus>
parseString(std::string_view data) noexcept
{
	bool quotesSeen = false;
	for (std::size_t tokenLength = 0; tokenLength < data.size(); tokenLength++) {
		switch (data[tokenLength]) {
		case 0:
			return {"", ParsingStatus::FAILURE};
		case '}':
			return {"", ParsingStatus::NO_DATA};
		case '\"': {
			if (!quotesSeen) {
				quotesSeen = true;
				continue;
			}
			return {data.substr(0, tokenLength), ParsingStatus::SUCCESS};
		}
		default: {
		}
		}
	}
	return {"", ParsingStatus::FAILURE};
}

struct ParsedJsonItem {
	std::string_view key;
	std::string_view value;
	ParsingStatus status;
};

constexpr static ParsedJsonItem parseJsonItem(std::string_view data) noexcept
{
	ParsedJsonItem res;
	const auto [key, keyParsingStatus] = parseString(data);
	res.status = keyParsingStatus;
	if (keyParsingStatus == ParsingStatus::FAILURE || keyParsingStatus == ParsingStatus::NO_DATA) {
		return res;
	}
	res.key = key;

	if (data[key.size()] != ':') {
		res.status = ParsingStatus::FAILURE;
		return res;
	}

	const auto [value, valueParsingStatus] = parseString(data.substr(key.size() + sizeof(':')));
	if (valueParsingStatus == ParsingStatus::FAILURE
		|| valueParsingStatus == ParsingStatus::NO_DATA) {
		res.status = ParsingStatus::FAILURE;
		return res;
	}
	res.value = value;
	return res;
}

constexpr static std::optional<std::size_t> findParsingStartPosition(std::string_view data) noexcept
{
	const std::size_t bracketPos = data.find('[');
	if (bracketPos == std::string_view::npos) {
		return std::nullopt;
	}
	return bracketPos + 1;
}

static auto makeJsonItemReader(std::string_view data) noexcept
{
	return std::views::iota(0) | std::views::transform([data](int) mutable {
			   const ParsedJsonItem res = parseJsonItem(data);
			   data = data.substr(res.key.size() + res.value.size() + sizeof(':'));
			   return res;
		   });
}

std::optional<std::string_view>
JsonParser::findValueByKey(std::string_view data, std::string_view key)
{
	const std::optional<std::size_t> startingPos = findParsingStartPosition(data);
	if (!startingPos) {
		return std::nullopt;
	}

	std::string_view value;
	std::size_t seenCount = 0;
	for (const ParsedJsonItem item : makeJsonItemReader(data)) {
		if (item.status == ParsingStatus::NO_DATA) {
			return seenCount == 1 ? std::make_optional(value) : std::nullopt;
		} else if (item.status == ParsingStatus::FAILURE) {
			return std::nullopt;
		} else if (item.key == key) {
			value = item.value;
			seenCount++;
		}
	}
	throw std::runtime_error("Unexpected data end");
}

constexpr static bool
setKeyToValue(auto& keysMapping, auto& keysParsed, std::string_view key, std::string_view value)
{
	auto it = std::find_if(keysMapping.begin(), keysMapping.end(), [&key](const auto& pair) {
		return pair.first == key;
	});

	if (it == keysMapping.end()) {
		return false;
	}

	it->second.get().assign(value);
	keysParsed[std::distance(keysMapping.begin(), it)] = true;
	return true;
}

struct AboutProgramMapping {
	AboutProgramMapping(JsonParser::AboutProgram& aboutProgram) noexcept
		: keysMapping(
			  {std::make_pair("name"sv, std::ref(aboutProgram.name)),
			   std::make_pair("username"sv, std::ref(aboutProgram.username))})
		, keysParsed {false}
	{
	}

	std::array<std::pair<std::string_view, std::reference_wrapper<std::string>>, 2> keysMapping;
	std::array<bool, 2> keysParsed;
};

template<class AboutType, class AboutMapping>
constexpr static std::optional<AboutType> parseAboutData(std::string_view jsonData) noexcept
{
	std::optional<std::size_t> startingPos = findParsingStartPosition(jsonData);
	if (!startingPos.has_value()) {
		return std::nullopt;
	}

	auto aboutData = std::make_optional<AboutType>();
	AboutMapping mapping(*aboutData);

	for (const ParsedJsonItem item : makeJsonItemReader(jsonData.substr(*startingPos))) {
		if (item.status == ParsingStatus::NO_DATA) {
			return std::all_of(
					   mapping.keysParsed.begin(),
					   mapping.keysParsed.end(),
					   [](bool parsed) { return parsed; })
				? aboutData
				: std::nullopt;
		}
		if (item.status == ParsingStatus::FAILURE) {
			return std::nullopt;
		}

		if (!setKeyToValue(mapping.keysMapping, mapping.keysParsed, item.key, item.value)) {
			return std::nullopt;
		}
	}
}

std::optional<JsonParser::AboutProgram>
JsonParser::parseJsonAboutProgram(std::string_view jsonData) noexcept
{
	return parseAboutData<JsonParser::AboutProgram, AboutProgramMapping>(jsonData);
}

struct AboutOSVersionMapping {
	AboutOSVersionMapping(JsonParser::AboutOSVersion& aboutOSVersion) noexcept
		: keysMapping(
			  {std::make_pair("arch"sv, std::ref(aboutOSVersion.arch)),
			   std::make_pair("build"sv, std::ref(aboutOSVersion.build)),
			   std::make_pair("hostname"sv, std::ref(aboutOSVersion.hostname)),
			   std::make_pair("major"sv, std::ref(aboutOSVersion.majorNumber)),
			   std::make_pair("minor"sv, std::ref(aboutOSVersion.minorNumber)),
			   std::make_pair("name"sv, std::ref(aboutOSVersion.name)),
			   std::make_pair("platform"sv, std::ref(aboutOSVersion.platform)),
			   std::make_pair("platform_like"sv, std::ref(aboutOSVersion.platformLike)),
			   std::make_pair("version"sv, std::ref(aboutOSVersion.version))})
		, keysParsed {false}
	{
	}

	std::array<std::pair<std::string_view, std::reference_wrapper<std::string>>, 9> keysMapping;
	std::array<bool, 9> keysParsed;
};

std::optional<JsonParser::AboutOSVersion>
JsonParser::parseJsonOSVersion(std::string_view jsonData) noexcept
{
	return parseAboutData<JsonParser::AboutOSVersion, AboutOSVersionMapping>(jsonData);
}

} // namespace ipxp::process::osquery
