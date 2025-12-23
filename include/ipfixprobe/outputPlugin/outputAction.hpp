
/**
 * @file
 * @brief Declaration of OutputAction.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <ranges>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace ipxp {

struct OutputAction {
	enum class Type : bool { Include, Exclude };

	struct GlobalAction {};

	struct PluginAction {
		std::string pluginName;
	};

	struct FieldAction {
		std::string pluginName;
		std::string fieldName;
	};

	Type type;
	std::variant<GlobalAction, PluginAction, FieldAction> action;

	OutputAction(std::string_view line);
};

std::vector<OutputAction> parseActions(std::string_view configurationContent);

} // namespace ipxp
