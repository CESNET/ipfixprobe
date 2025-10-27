/**
 * @file serviceFilter.cpp
 * @brief Definition of ServiceFilter for DNS-SD service filtering.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "serviceFilter.hpp"

#include <algorithm>
#include <fstream>
#include <ranges>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace ipxp::process::dnssd {

constexpr static bool alwaysMatcher(std::string_view, std::string_view) noexcept
{
	return true;
}

constexpr static bool neverMatcher(std::string_view, std::string_view) noexcept
{
	return false;
}

static std::unordered_map<std::string, std::vector<std::string>>
parseWhitelist(std::string_view filename)
{
	std::unordered_map<std::string, std::vector<std::string>> res;

	std::ifstream file(filename.data());
	if (!file.is_open()) {
		throw std::runtime_error("Could not open whitelist file: " + std::string(filename));
	}

	std::string content {std::istreambuf_iterator<char>(file), {}};
	std::ranges::for_each(content | std::views::split('\n'), [&res](const auto& line) {
		auto tokens = line | std::views::split(',');
		if (tokens.empty()) {
			return;
		}

		auto txtValues = tokens | std::views::drop(1) | std::views::transform([](auto&& subrange) {
							 return std::string(subrange.begin(), subrange.end());
						 })
			| std::ranges::to<std::vector>();
		res[std::string(tokens.front().begin(), tokens.front().end())] = std::move(txtValues);
	});

	if (res.empty()) {
		throw std::runtime_error("Whitelist file is empty: " + std::string(filename));
	}

	return res;
}

static bool listMatcher(
	const std::unordered_map<std::string, std::vector<std::string>>& whitelist,
	std::string_view service,
	std::string_view txtValue)
{
	auto serviceIt = whitelist.find(std::string(service));
	if (serviceIt == whitelist.end()) {
		return false;
	}

	// return serviceIt->second.contains(std::string(txtValue));
	return std::ranges::find(serviceIt->second, txtValue) != serviceIt->second.end();
}

ServiceFilter::ServiceFilter(const DNSSDOptionsParser::TxtProcessingMode& mode)
{
	if (!mode.has_value()) {
		m_matcher = neverMatcher;
		return;
	}

	if (std::holds_alternative<DNSSDOptionsParser::ProcessAllTxtRecords>(*mode)) {
		m_matcher = alwaysMatcher;
		return;
	}

	m_matcher
		= [whitelist = parseWhitelist(std::get<std::string>(*mode))](
			  std::string_view service,
			  std::string_view txtValue) { return listMatcher(whitelist, service, txtValue); };
}

bool ServiceFilter::matches(std::string_view service, std::string_view txtValue) const noexcept
{
	return m_matcher(service, txtValue);
}

} // namespace ipxp