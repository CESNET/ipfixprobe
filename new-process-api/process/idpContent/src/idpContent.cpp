/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "idpContent.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

#include "idpContentData.hpp"

namespace ipxp {

static const PluginManifest idpcontentPluginManifest = {
	.name = "idpcontent",
	.description = "Idpcontent process plugin for parsing idpcontent traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser("idpcontent", "Parse first bytes of flow payload");
			parser.usage(std::cout);*/
		},
};

const inline std::vector<FieldPair<IDPContentFields>> fields = {
	{IDPContentFields::IDP_CONTENT, "IDP_CONTENT"},
	{IDPContentFields::IDP_CONTENT_REV, "IDP_CONTENT_REV"},
};

static FieldSchema createIDPContentSchema(FieldManager& fieldManager, FieldHandlers<IDPContentFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("idpcontent");

	auto [contentField, contentRevField] = schema.addVectorField<uint8_t>(
		"IDP_CONTENT", "IDP_CONTENT_REV",
		[](const void* context) { return {toSpan(
			reinterpret_cast<const IDPContentExport*>(context)->directionalContent[Direction::Forward])}; },
		[](const void* context) { return {toSpan(
			reinterpret_cast<const IDPContentExport*>(context)->directionalContent[Direction::Reverse])}; }
		);
	handlers.insert(IDPContentFields::IDP_CONTENT, contentField);
	handlers.insert(IDPContentFields::IDP_CONTENT_REV, contentRevField);

	return schema;
}

IDPContentPlugin::IDPContentPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createIDPContentSchema(manager, m_fieldHandlers);
}

UpdateRequirement IDPContentPlugin::updateContent(FlowRecord& flowRecord, const Packet& packet) noexcept
{
	// Check zero-packets and be sure, that the exported content is from both directions
	if (m_exportData.directionalContent[packet.direction].has_value()) {
		return m_exportData.directionalContent[static_cast<Direction>(!packet.direction)].has_value()
				? UpdateRequirement::NoUpdateNeeded
				: UpdateRequirement::RequiresUpdate;
	}

	if (packet.payload.empty()) {
		return UpdateRequirement::RequiresUpdate;
	}

	const std::size_t sizeToSave = std::min(IDPContentData::MAX_CONTENT_LENGTH, packet.payload.size());
	m_exportData.directionalContent[packet.direction] = std::make_optional<IDPContentExport::Content>(
		packet.payload.data(), packet.payload.data() + sizeToSave);
	m_fieldHandlers[fields[packet.direction].first].setAsAvailable(flowRecord);

	return UpdateRequirement::RequiresUpdate;
}

PluginInitResult IDPContentPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<IDPContentExport*>(pluginContext));
	UpdateRequirement updateRequirement = updateContent(flowContext.flowRecord, flowContext.packet, *pluginData);
	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = updateRequirement,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult IDPContentPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	UpdateRequirement updateRequirement = updateContent(flowContext.flowRecord, flowContext.packet, *pluginData);
	return {
		.updateRequirement = updateRequirement,
		.flowAction = FlowAction::NoAction,
	};
}

void IDPContentPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<IDPContentExport*>(pluginContext));
}

std::string IDPContentPlugin::getName() const noexcept
{ 
	return idpcontentPluginManifest.name; 
}

static const PluginRegistrar<IDPContentPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	idpcontentRegistrar(idpcontentPluginManifest);

} // namespace ipxp
