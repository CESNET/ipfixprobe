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

#include "idpContentGetters.hpp"

#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils/spanUtils.hpp>

namespace ipxp::process::idpContent {

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
		[](const void* context) { return getIDPContentField(context, Direction::Forward); },
		[](const void* context) { return getIDPContentField(context, Direction::Reverse); });
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

bool IDPContentPlugin::updateContent(
	FlowRecord& flowRecord,
	const amon::Packet& packet,
	const Direction direction,
	IDPContentContext& idpContext) noexcept
{
	// Check zero-packets and be sure, that the exported content is from both directions
	if (idpContext.directionalContent[direction].has_value()) {
		return !idpContext.directionalContent[!direction].has_value();
	}

	const std::optional<std::size_t> ipPayloadLength = getIPPayloadLength(packet);
	if (!ipPayloadLength.has_value() || *ipPayloadLength == 0) {
		return true;
	}

	const std::size_t sizeToSave
		= std::min<size_t>(IDPContentContext::MAX_CONTENT_LENGTH, *ipPayloadLength);
	std::span<const std::byte> payload = getPayload(packet);
	idpContext.directionalContent[direction] = std::make_optional<IDPContentContext::Content>(
		payload.data(),
		payload.data() + sizeToSave);
	m_fieldHandlers[direction ? IDPContentFields::IDP_CONTENT : IDPContentFields::IDP_CONTENT_REV]
		.setAsAvailable(flowRecord);

	return true;
}

OnInitResult IDPContentPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto& idpContext = *std::construct_at(reinterpret_cast<IDPContentContext*>(pluginContext));
	updateContent(
		flowContext.flowRecord,
		*flowContext.packetContext.packet,
		flowContext.packetDirection,
		idpContext);

	return OnInitResult::ConstructedNeedsUpdate;
}

OnUpdateResult IDPContentPlugin::onUpdate(const FlowContext& flowContext, void* pluginContext)
{
	auto& pluginData = *reinterpret_cast<IDPContentContext*>(pluginContext);
	const bool requiresUpdate = updateContent(
		flowContext.flowRecord,
		*flowContext.packetContext.packet,
		flowContext.packetDirection,
		pluginData);
	return requiresUpdate ? OnUpdateResult::NeedsUpdate : OnUpdateResult::Final;
}

void IDPContentPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<IDPContentContext*>(pluginContext));
}

PluginDataMemoryLayout IDPContentPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(IDPContentContext),
		.alignment = alignof(IDPContentContext),
	};
}

static const PluginRegistrar<
	IDPContentPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	idpcontentRegistrar(idpcontentPluginManifest);

} // namespace ipxp::process::idpContent
