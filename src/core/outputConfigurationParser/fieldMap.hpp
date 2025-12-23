/**
 * @file
 * @brief Implementation of FieldMap that applies OutputActions to available fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "outputAction.hpp"

#include <ranges>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include <fieldDescriptor.hpp>

namespace ipxp {

class FieldMap {
public:
	constexpr FieldMap(const std::vector<process::FieldDescriptor>& availableFields) noexcept
	{
		std::ranges::for_each(availableFields, [&](const process::FieldDescriptor& field) {
			m_map[field.getGroup()][field.getName()] = &field;
		});
	}

	constexpr std::vector<const process::FieldDescriptor*>
	applyActions(const std::vector<OutputAction>& actions) const
	{
		std::vector<const process::FieldDescriptor*> res;
		applyGlobalAction(res, OutputAction::Type::Include);

		for (const OutputAction& action : actions) {
			if (std::holds_alternative<OutputAction::GlobalAction>(action.action)) {
				applyGlobalAction(res, action.type);
			} else if (std::holds_alternative<OutputAction::PluginAction>(action.action)) {
				applyPluginAction(res, action);
			} else if (std::holds_alternative<OutputAction::FieldAction>(action.action)) {
				applyFieldAction(res, action);
			}
		}

		std::ranges::sort(res);
		res.erase(std::ranges::unique(res).begin(), res.end());
		return res;
	}

private:
	void applyGlobalAction(
		std::vector<const process::FieldDescriptor*>& res,
		const OutputAction::Type type) const noexcept
	{
		if (type == OutputAction::Type::Include) {
			const auto allFields = m_map | std::views::values | std::views::join
				| std::views::transform([](const auto& pair) { return pair.second; })
				| std::ranges::to<std::vector>();
			res.insert(res.end(), allFields.begin(), allFields.end());
		} else {
			res.clear();
		}
	}

	void applyPluginAction(
		std::vector<const process::FieldDescriptor*>& res,
		const OutputAction& action) const
	{
		const OutputAction::PluginAction& pluginAction
			= std::get<OutputAction::PluginAction>(action.action);
		if (action.type == OutputAction::Type::Include) {
			auto pluginIt = m_map.find(pluginAction.pluginName);
			if (pluginIt == m_map.end()) {
				throw std::invalid_argument(
					"Plugin name '" + pluginAction.pluginName
					+ "' not found among available plugins.");
			}
			const auto pluginFields
				= pluginIt->second | std::views::values | std::ranges::to<std::vector>();
			res.insert(res.end(), pluginFields.begin(), pluginFields.end());
		} else {
			res.erase(
				std::remove_if(
					res.begin(),
					res.end(),
					[&](const process::FieldDescriptor* field) {
						return field->getGroup() == pluginAction.pluginName;
					}),
				res.end());
		}
	}

	void applyFieldAction(
		std::vector<const process::FieldDescriptor*>& res,
		const OutputAction& action) const
	{
		const OutputAction::FieldAction& fieldAction
			= std::get<OutputAction::FieldAction>(action.action);
		if (action.type == OutputAction::Type::Include) {
			auto pluginIt = m_map.find(fieldAction.pluginName);
			if (pluginIt == m_map.end()) {
				throw std::invalid_argument(
					"Plugin name '" + fieldAction.pluginName
					+ "' not found among available plugins.");
			}
			auto fieldIt = pluginIt->second.find(fieldAction.fieldName);
			if (fieldIt == pluginIt->second.end()) {
				throw std::invalid_argument(
					"Field name '" + fieldAction.fieldName + "' not found in plugin '"
					+ fieldAction.pluginName + "'.");
			}
			res.push_back(fieldIt->second);
		} else {
			res.erase(
				std::remove_if(
					res.begin(),
					res.end(),
					[&](const process::FieldDescriptor* field) {
						return field->getGroup() == fieldAction.pluginName
							&& field->getName() == fieldAction.fieldName;
					}),
				res.end());
		}
	}

	std::unordered_map<
		std::string_view,
		std::unordered_map<std::string_view, const process::FieldDescriptor*>>
		m_map;
};

} // namespace ipxp