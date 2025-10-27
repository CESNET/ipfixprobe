/**
 * @file
 * @brief Plugin for parsing mpls traffic.
 * @author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts MPLS top label from packets,
 * stores them in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "mpls.hpp"

#include "mplsContext.hpp"
#include "mplsGetters.hpp"

#include <iostream>

#include <amon/layers/MPLS.hpp>
#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils/spanUtils.hpp>

namespace ipxp::process::mpls {

static const PluginManifest mplsPluginManifest = {
	.name = "mpls",
	.description = "Mpls process plugin for parsing mpls traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser("mpls", "Parse MPLS traffic");
			parser.usage(std::cout);
		},
};

static FieldGroup
createMPLSSchema(FieldManager& fieldManager, FieldHandlers<MPLSFields>& handlers) noexcept
{
	FieldGroup schema = fieldManager.createFieldGroup("mpls");

	handlers.insert(
		MPLSFields::MPLS_TOP_LABEL_STACK_SECTION,
		schema.addScalarField("MPLS_TOP_LABEL_STACK_SECTION", getMPLSTopLabelStackSectionField));

	return schema;
}

MPLSPlugin::MPLSPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createMPLSSchema(manager, m_fieldHandlers);
}

OnInitResult MPLSPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	auto mplsView = getLayerView<amon::layers::MPLSView>(
		*flowContext.packetContext.packet,
		flowContext.packetContext.packet->layout.l3);
	if (!mplsView.has_value()) {
		return OnInitResult::Irrelevant;
	}

	auto& mplsContext = *std::construct_at(reinterpret_cast<MPLSContext*>(pluginContext));
	mplsContext.topLabel = mplsView->label();
	m_fieldHandlers[MPLSFields::MPLS_TOP_LABEL_STACK_SECTION].setAsAvailable(
		flowContext.flowRecord);
	return OnInitResult::ConstructedFinal;
}

void MPLSPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<MPLSContext*>(pluginContext));
}

PluginDataMemoryLayout MPLSPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(MPLSContext),
		.alignment = alignof(MPLSContext),
	};
}

static const PluginRegistrar<
	MPLSPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	mplsRegistrar(mplsPluginManifest);

} // namespace ipxp::process::mpls
