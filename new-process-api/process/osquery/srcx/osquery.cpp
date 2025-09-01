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

#include "osquery.hpp"

#include <iostream>

#include <pluginManifest.hpp>
#include <pluginRegistrar.hpp>
#include <pluginFactory.hpp>
#include <fieldSchema.hpp>
#include <fieldManager.hpp>

#include "osqueryData.hpp"

namespace ipxp {

static const PluginManifest osqueryPluginManifest = {
	.name = "osquery",
	.description = "Osquery process plugin for parsing osquery traffic.",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			/*OptionsParser parser(
				"osquery",
				"Collect information about locally outbound flows from OS");
			parser.usage(std::cout);*/
		},
};

static FieldSchema createOSQuerySchema(FieldManager& manager, FieldHandlers<OSQueryFields>& handlers) noexcept
{
	FieldSchema schema = fieldManager.createFieldSchema("osquery");

	handlers.insert(OSQueryFields::OSQUERY_PROGRAM_NAME, schema.addScalarField(
		"OSQUERY_PROGRAM_NAME",
		[] (const void* context) { return toStringView(static_cast<const OSQueryExport*>(context)->programName); }
	));
	handlers.insert(OSQueryFields::OSQUERY_USERNAME, schema.addScalarField(
		"OSQUERY_USERNAME",
		[] (const void* context) { return toStringView(static_cast<const OSQueryExport*>(context)->username); }
	));
	handlers.insert(OSQueryFields::OSQUERY_OS_NAME, schema.addScalarField(
		"OSQUERY_OS_NAME",
		[] (const void* context) { return toStringView(static_cast<const OSQueryExport*>(context)->osName); }
	));
	handlers.insert(OSQueryFields::OSQUERY_OS_MAJOR, schema.addScalarField(
		"OSQUERY_OS_MAJOR",
		[] (const void* context) { return static_cast<const OSQueryExport*>(context)->majorNumber; }
	));
	handlers.insert(OSQueryFields::OSQUERY_OS_MINOR, schema.addScalarField(
		"OSQUERY_OS_MINOR",
		[] (const void* context) { return static_cast<const OSQueryExport*>(context)->minorNumber; }
	));
	handlers.insert(OSQueryFields::OSQUERY_OS_BUILD, schema.addScalarField(
		"OSQUERY_OS_BUILD",
		[] (const void* context) { return toStringView(static_cast<const OSQueryExport*>(context)->osBuild); }
	));
	handlers.insert(OSQueryFields::OSQUERY_OS_PLATFORM, schema.addScalarField(
		"OSQUERY_OS_PLATFORM",
		[] (const void* context) { return toStringView(static_cast<const OSQueryExport*>(context)->osPlatform); }
	));
	handlers.insert(OSQueryFields::OSQUERY_OS_PLATFORM_LIKE, schema.addScalarField(
		"OSQUERY_OS_PLATFORM_LIKE",
		[] (const void* context) { return toStringView(static_cast<const OSQueryExport*>(context)->osPlatformLike); }
	));
	handlers.insert(OSQueryFields::OSQUERY_OS_ARCH, schema.addScalarField(
		"OSQUERY_OS_ARCH",
		[] (const void* context) { return toStringView(static_cast<const OSQueryExport*>(context)->osArch); }
	));
	handlers.insert(OSQueryFields::OSQUERY_KERNEL_VERSION, schema.addScalarField(
		"OSQUERY_KERNEL_VERSION",
		[] (const void* context) { return toStringView(static_cast<const OSQueryExport*>(context)->kernelVersion); }
	));
	handlers.insert(OSQueryFields::OSQUERY_SYSTEM_HOSTNAME, schema.addScalarField(
		"OSQUERY_SYSTEM_HOSTNAME",
		[] (const void* context) { return toStringView(static_cast<const OSQueryExport*>(context)->systemHostname); }
	));
	
	return schema;
}

OSQueryPlugin::OSQueryPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	createOSQuerySchema(manager, m_fieldHandlers);
}

PluginInitResult OSQueryPlugin::onInit(const FlowContext& flowContext, void* pluginContext)
{
	if (const std::optional<JsonParser::AboutProgram> programInfo
			= manager.readInfoAboutProgram(flowRecord.flowKey); programInfo.has_value()) {
		//TODO FIX GLOBAL COUNTERS
		//numberOfSuccessfullyRequests++;
		auto* pluginData = std::construct_at(reinterpret_cast<OSQueryData*>(pluginContext));
		pluginData->programName = programInfo->name;
    	pluginData->username = programInfo->username;
		return {
			.constructionState = ConstructionState::Constructed,
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}

	return {
		.constructionState = ConstructionState::NotConstructed,
		.updateRequirement = UpdateRequirement::NoUpdateNeeded,
		.flowAction = FlowAction::RemovePlugin,
	};
}

void OSQueryPlugin::onDestroy(void* pluginContext)
{
	std::destroy_at(reinterpret_cast<OSQueryData*>(pluginContext));
}

PluginDataMemoryLayout OSQueryPlugin::getDataMemoryLayout() const noexcept
{
	return {
		.fieldCount = static_cast<uint32_t>(OSQueryData),
		.fieldSize = sizeof(OSQueryData),
	};
}



// TODO readInfoAboutOS once in all constructors

/*
void OSQUERYPlugin::init(const char* params)
{
	if (const std::optional<JsonParser::AboutOSVersion> osVersionInfo 
			= manager.readInfoAboutOS(); osVersionInfo.has_value()) {
		m_exportData.osName = osVersionInfo->name;
		m_exportData.majorNumber = osVersionInfo->majorNumber;
		m_exportData.minorNumber = osVersionInfo->minorNumber;
		m_exportData.osBuild = osVersionInfo->build;
		m_exportData.osPlatform = osVersionInfo->platform;
		m_exportData.osPlatformLike = osVersionInfo->platformLike;
		m_exportData.osArch = osVersionInfo->arch;
		m_exportData.kernelVersion = osVersionInfo->version;
		m_exportData.systemHostname = osVersionInfo->hostname;
	}
}

void OSQUERYPlugin::finish(bool print_stats)
{
	if (print_stats) {
		std::cout << "OSQUERY plugin stats:" << std::endl;
		std::cout << "Number of successfully processed requests: " << numberOfSuccessfullyRequests
				  << std::endl;
	}
}*/

std::string OSQueryPlugin::getName() const noexcept
{
	return osqueryPluginManifest.name;
}

static const PluginRegistrar<OSQueryPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	osqueryRegistrar(osqueryPluginManifest);

} // namespace ipxp
