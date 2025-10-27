/**
 * @file
 * @brief Plugin for parsing osquery traffic.
 * @author Anton Aheyeu aheyeant@fit.cvut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that queries OS to obtain info about flows,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "osquery.hpp"

#include "osqueryContext.hpp"
#include "osqueryGetters.hpp"

#include <iostream>

#include <fieldGroup.hpp>
#include <fieldManager.hpp>
#include <flowRecord.hpp>
#include <ipfixprobe/options.hpp>
#include <pluginFactory.hpp>
#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <utils/stringViewUtils.hpp>

namespace ipxp::process::osquery {

static const PluginManifest osqueryPluginManifest = {
	.name = "osquery",
	.description = "Osquery process plugin for parsing osquery traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			OptionsParser parser(
				"osquery",
				"Collect information about locally outbound flows from OS");
			parser.usage(std::cout);
		},
};

static FieldGroup
createOSQuerySchema(FieldManager& manager, FieldHandlers<OSQueryFields>& handlers) noexcept
{
	FieldGroup schema = manager.createFieldGroup("osquery");

	handlers.insert(
		OSQueryFields::OSQUERY_PROGRAM_NAME,
		schema.addScalarField("OSQUERY_PROGRAM_NAME", getOSQueryProgramNameField));

	handlers.insert(
		OSQueryFields::OSQUERY_USERNAME,
		schema.addScalarField("OSQUERY_USERNAME", getOSQueryUsernameField));

	handlers.insert(
		OSQueryFields::OSQUERY_OS_NAME,
		schema.addScalarField("OSQUERY_OS_NAME", getOSQueryOSNameField));

	handlers.insert(
		OSQueryFields::OSQUERY_OS_MAJOR,
		schema.addScalarField("OSQUERY_OS_MAJOR", getOSQueryOSMajorField));

	handlers.insert(
		OSQueryFields::OSQUERY_OS_MINOR,
		schema.addScalarField("OSQUERY_OS_MINOR", getOSQueryOSMinorField));

	handlers.insert(
		OSQueryFields::OSQUERY_OS_BUILD,
		schema.addScalarField("OSQUERY_OS_BUILD", getOSQueryOSBuildField));

	handlers.insert(
		OSQueryFields::OSQUERY_OS_PLATFORM,
		schema.addScalarField("OSQUERY_OS_PLATFORM", getOSQueryOSPlatformField));

	handlers.insert(
		OSQueryFields::OSQUERY_OS_PLATFORM_LIKE,
		schema.addScalarField("OSQUERY_OS_PLATFORM_LIKE", getOSQueryOSPlatformLikeField));

	handlers.insert(
		OSQueryFields::OSQUERY_OS_ARCH,
		schema.addScalarField("OSQUERY_OS_ARCH", getOSQueryOSArchField));

	handlers.insert(
		OSQueryFields::OSQUERY_KERNEL_VERSION,
		schema.addScalarField("OSQUERY_KERNEL_VERSION", getOSQueryKernelVersionField));

	handlers.insert(
		OSQueryFields::OSQUERY_SYSTEM_HOSTNAME,
		schema.addScalarField("OSQUERY_SYSTEM_HOSTNAME", getOSQuerySystemHostnameField));

	return schema;
}

OSQueryPlugin::OSQueryPlugin([[maybe_unused]] const std::string& params, FieldManager& manager)
{
	createOSQuerySchema(manager, m_fieldHandlers);
	m_osVersionInfo = m_requestManager.readInfoAboutOS();
	if (!m_osVersionInfo.has_value()) {
		throw std::runtime_error("Failed to obtain OS version info from osquery.");
	}
}

OnInitResult OSQueryPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	const std::optional<JsonParser::AboutProgram> programInfo
		= m_requestManager.readInfoAboutProgram(flowContext.flowRecord.flowKey);
	if (programInfo.has_value()) {
		auto& osqueryContext = *std::construct_at(reinterpret_cast<OSQueryContext*>(pluginContext));
		osqueryContext.programName = programInfo->name;
		osqueryContext.username = programInfo->username;

		return OnInitResult::ConstructedFinal;
	}

	return OnInitResult::Irrelevant;
}

OnExportResult OSQueryPlugin::onExport(const FlowRecord& flowRecord, void* pluginContext)
{
	auto& osqueryContext = *reinterpret_cast<OSQueryContext*>(pluginContext);

	osqueryContext.osName = m_osVersionInfo->name;
	osqueryContext.majorNumber = m_osVersionInfo->majorNumber;
	osqueryContext.minorNumber = m_osVersionInfo->minorNumber;
	osqueryContext.osBuild = m_osVersionInfo->build;
	osqueryContext.osPlatform = m_osVersionInfo->platform;
	osqueryContext.osPlatformLike = m_osVersionInfo->platformLike;
	osqueryContext.osArch = m_osVersionInfo->arch;
	osqueryContext.kernelVersion = m_osVersionInfo->version;
	osqueryContext.systemHostname = m_osVersionInfo->hostname;

	return OnExportResult::NoAction;
}

void OSQueryPlugin::onDestroy(void* pluginContext) noexcept
{
	std::destroy_at(reinterpret_cast<OSQueryContext*>(pluginContext));
}

PluginDataMemoryLayout OSQueryPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.size = sizeof(OSQueryContext),
		.alignment = alignof(OSQueryContext),
	};
}

static const PluginRegistrar<
	OSQueryPlugin,
	PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	osqueryRegistrar(osqueryPluginManifest);

} // namespace ipxp::process::osquery
