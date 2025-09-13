/**
 * @file
 * @brief Plugin for parsing idpcontent traffic.
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that exports packet payloads as IDP content,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 * 
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "idpContent.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>
#include <utils/spanUtils.hpp>


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

static FieldSchema createIDPContentSchema(FieldManager& fieldManager, FieldHandlers<IDPContentFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("idpcontent");

	auto [contentField, contentRevField] = schema.addVectorDirectionalFields(
		"IDP_CONTENT", "IDP_CONTENT_REV",
		[](const void* context) { return toSpan<const std::byte>(
			*reinterpret_cast<const IDPContentData*>(context)->directionalContent[Direction::Forward]); },
		[](const void* context) { return toSpan<const std::byte>(
			*reinterpret_cast<const IDPContentData*>(context)->directionalContent[Direction::Reverse]); }
		);
	handlers.insert(IDPContentFields::IDP_CONTENT, contentField);
	handlers.insert(IDPContentFields::IDP_CONTENT_REV, contentRevField);

	return schema;
}

IDPContentPlugin::IDPContentPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createIDPContentSchema(manager, m_fieldHandlers);
}

UpdateRequirement IDPContentPlugin::updateContent(FlowRecord& flowRecord, const Packet& packet, IDPContentData& pluginData) noexcept
{
	// Check zero-packets and be sure, that the exported content is from both directions
	if (pluginData.directionalContent[packet.source_pkt].has_value()) {
		return pluginData.directionalContent[static_cast<Direction>(!packet.source_pkt)].has_value()
				? UpdateRequirement::NoUpdateNeeded
				: UpdateRequirement::RequiresUpdate;
	}

	if (packet.payload_len == 0) {
		return UpdateRequirement::RequiresUpdate;
	}

	const std::size_t sizeToSave = std::min<size_t>(IDPContentData::MAX_CONTENT_LENGTH, packet.payload_len);
	pluginData.directionalContent[packet.source_pkt] = std::make_optional<IDPContentData::Content>(
		reinterpret_cast<const std::byte*>(packet.payload), reinterpret_cast<const std::byte*>(packet.payload) + sizeToSave);
	m_fieldHandlers[packet.source_pkt ? IDPContentFields::IDP_CONTENT : IDPContentFields::IDP_CONTENT_REV].setAsAvailable(flowRecord);

	return UpdateRequirement::RequiresUpdate;
}

PluginInitResult IDPContentPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<IDPContentData*>(pluginContext));
	UpdateRequirement updateRequirement = updateContent(flowContext.flowRecord, flowContext.packet, *pluginData);
	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = updateRequirement,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult IDPContentPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<IDPContentData*>(pluginContext);
	UpdateRequirement updateRequirement = updateContent(flowContext.flowRecord, flowContext.packet, *pluginData);
	return {
		.updateRequirement = updateRequirement,
		.flowAction = FlowAction::NoAction,
	};
}

void IDPContentPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<IDPContentData*>(pluginContext));
}

static const PluginRegistrar<IDPContentPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	idpcontentRegistrar(idpcontentPluginManifest);

} // namespace ipxp
