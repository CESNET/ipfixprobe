/**
 * @file
 * @brief Implementation of OutputAction.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "outputAction.hpp"

#include <algorithm>
#include <cctype>
#include <functional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace ipxp {

// Helper because std::isspace takes int
constexpr static bool isSpace(const char c) noexcept
{
	return std::isspace(c);
}

OutputAction::OutputAction(std::string_view line)
{
	if (std::ranges::any_of(line, isSpace)) {
		throw std::invalid_argument(
			"Invalid field specification: " + std::string(line)
			+ ". No whitespace characters are allowed.");
	}

	type = line.starts_with('-') ? Type::Exclude : Type::Include;
	if (type == Type::Exclude) {
		line.remove_prefix(1);
	}

	if (line.contains(".")) {
		if (std::ranges::count(line, '.') != 1) {
			throw std::invalid_argument(
				"Invalid field specification: " + std::string(line)
				+ ". Only one '.' is allowed to separate plugin and field name.");
		}
		const std::size_t dotPos = line.find('.');
		action = FieldAction {
			.pluginName = std::string(line.substr(0, dotPos)),
			.fieldName = std::string(line.substr(dotPos + 1))};
		return;
	}

	if (line == "*") {
		action = GlobalAction {};
		return;
	}

	action = PluginAction {std::string(line)};
}

constexpr static std::string_view trimFieldsHeader(std::string_view content)
{
	std::string_view header = "fields:";
	if (!content.starts_with(header)) {
		throw std::invalid_argument("Configuration file must start with \"fields:\" header");
	}

	content.remove_prefix(header.size());
	const std::size_t firstQuotePos
		= std::ranges::find_if(content, std::not_fn(isSpace)) - content.begin();
	if (firstQuotePos == content.size() || content[firstQuotePos] != '\'') {
		throw std::invalid_argument(
			"Configuration file must contain opening quote after \"fields:\" header");
	}

	const std::size_t lastQuotePos = content.size() - 1
		- (std::find_if(content.rbegin(), content.rend(), std::not_fn(isSpace)) - content.rbegin());
	if (lastQuotePos == -1ULL || content[lastQuotePos] != '\'') {
		throw std::invalid_argument(
			"Configuration file must contain closing quote after field definitions");
	}

	return content.substr(firstQuotePos + 1, lastQuotePos - firstQuotePos - 1);
}

constexpr static std::string removeComments(std::string_view content) noexcept
{
	std::string result(content.begin(), content.end());
	for (std::size_t sharpPos = result.find('#'); sharpPos != std::string::npos;
		 sharpPos = result.find('#', sharpPos)) {
		const std::size_t endOfLinePos = result.find('\n', sharpPos);
		if (endOfLinePos == std::string::npos) {
			result.erase(sharpPos);
		} else {
			result.erase(sharpPos, endOfLinePos - sharpPos + 1);
		}
	}

	return result;
}

std::vector<OutputAction> parseActions(std::string_view configurationContent)
{
	return removeComments(trimFieldsHeader(configurationContent)) | std::views::split(',')
		| std::views::transform([](const auto lineRange) {
			   return std::string_view(&*lineRange.begin(), std::ranges::distance(lineRange));
		   })
		// Remove empty lines
		| std::views::filter([](std::string_view line) {
			   return std::ranges::find_if(line, std::not_fn(isSpace)) != line.end();
		   })
		// Trim spaces on the sides
		| std::views::transform([](std::string_view line) {
			   const std::size_t firstNonSpacePos
				   = std::ranges::find_if(line, std::not_fn(isSpace)) - line.begin();
			   const std::size_t lastNonSpacePos = line.size() - 1
				   - (std::find_if(line.rbegin(), line.rend(), std::not_fn(isSpace))
					  - line.rbegin());
			   return line.substr(firstNonSpacePos, lastNonSpacePos - firstNonSpacePos + 1);
		   })
		| std::views::transform([](std::string_view line) { return OutputAction(line); })
		| std::ranges::to<std::vector>();
}

} // namespace ipxp