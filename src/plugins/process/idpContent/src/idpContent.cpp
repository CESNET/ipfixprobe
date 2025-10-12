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

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils/spanUtils.hpp>

namespace ipxp {

static const PluginManifest idpcontentPluginManifest = {
	.name = "idpcontent",
	.description = "Idpcontent process plugin for parsing idpcontent traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("idpcontent", "Parse first bytes of flow payload");
			parser.usage(std::cout);
		},
};

static FieldGroup createIDPContentSchema(
	FieldManager& fieldManager,
	FieldHandlers<IDPContentFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("idpcontent");

	auto [contentField, contentRevField] = schema.addVectorDirectionalFields(
		"IDP_CONTENT",
		"IDP_CONTENT_REV",
		[](const void* context) {
			return toSpan<const std::byte>(*reinterpret_cast<const IDPContentData*>(context)
												->directionalContent[Direction::Forward]);
		},
		[](const void* context) {
			return toSpan<const std::byte>(*reinterpret_cast<const IDPContentData*>(context)
												->directionalContent[Direction::Reverse]);
		});
	handlers.insert(IDPContentFields::IDP_CONTENT, contentField);
	handlers.insert(IDPContentFields::IDP_CONTENT_REV, contentRevField);

	return schema;
}

IDPContentPlugin::IDPContentPlugin(
	[[maybe_unused]] const std::string& params,
	FieldManager& manager)
{
	createIDPContentSchema(manager, m_fieldHandlers);
}

UpdateRequirement IDPContentPlugin::updateContent(
	FlowRecord& flowRecord,
	const amon::Packet& packet,
	const PacketFeatures& features,
	IDPContentData& pluginData) noexcept
{
	// Check zero-packets and be sure, that the exported content is from both directions
	if (pluginData.directionalContent[features.direction].has_value()) {
		return pluginData.directionalContent[!features.direction].has_value()
			? UpdateRequirement::NoUpdateNeeded
			: UpdateRequirement::RequiresUpdate;
	}

	if (features.ipPayloadLength == 0) {
		return UpdateRequirement::RequiresUpdate;
	}

	const std::size_t sizeToSave
		= std::min<size_t>(IDPContentData::MAX_CONTENT_LENGTH, features.ipPayloadLength);
	std::span<const std::byte> payload = getPayload(packet);
	pluginData.directionalContent[features.direction]
		= std::make_optional<IDPContentData::Content>(payload.data(), payload.data() + sizeToSave);
	m_fieldHandlers
		[features.direction ? IDPContentFields::IDP_CONTENT : IDPContentFields::IDP_CONTENT_REV]
			.setAsAvailable(flowRecord);

	return UpdateRequirement::RequiresUpdate;
}

PluginInitResult IDPContentPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = std::construct_at(reinterpret_cast<IDPContentData*>(pluginContext));
	UpdateRequirement updateRequirement = updateContent(
		flowContext.flowRecord,
		flowContext.packet,
		flowContext.features,
		*pluginData);
	return {
		.constructionState = ConstructionState::Constructed,
		.updateRequirement = updateRequirement,
		.flowAction = FlowAction::NoAction,
	};
}

PluginUpdateResult IDPContentPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto* pluginData = reinterpret_cast<IDPContentData*>(pluginContext);
	UpdateRequirement updateRequirement = updateContent(
		flowContext.flowRecord,
		flowContext.packet,
		flowContext.features,
		*pluginData);
	return {
		.updateRequirement = updateRequirement,
		.flowAction = FlowAction::NoAction,
	};
}

void IDPContentPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<IDPContentData*>(pluginContext));
}

PluginDataMemoryLayout IDPContentPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(IDPContentData),
		.alignment = alignof(IDPContentData),
	};
}

static const PluginRegistrar<
	IDPContentPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	idpcontentRegistrar(idpcontentPluginManifest);

} // namespace ipxp
