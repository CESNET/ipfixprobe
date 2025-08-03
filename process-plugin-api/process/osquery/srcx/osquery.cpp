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

const inline std::vector<FieldPair<OSQueryFields>> fields = {
	{OSQueryFields::OSQUERY_PROGRAM_NAME, "OSQUERY_PROGRAM_NAME"},
	{OSQueryFields::OSQUERY_USERNAME, "OSQUERY_USERNAME"},
	{OSQueryFields::OSQUERY_OS_NAME, "OSQUERY_OS_NAME"},
	{OSQueryFields::OSQUERY_OS_MAJOR, "OSQUERY_OS_MAJOR"},
	{OSQueryFields::OSQUERY_OS_MINOR, "OSQUERY_OS_MINOR"},
	{OSQueryFields::OSQUERY_OS_BUILD, "OSQUERY_OS_BUILD"},
	{OSQueryFields::OSQUERY_OS_PLATFORM, "OSQUERY_OS_PLATFORM"},
	{OSQueryFields::OSQUERY_OS_PLATFORM_LIKE, "OSQUERY_OS_PLATFORM_LIKE"},
	{OSQueryFields::OSQUERY_OS_ARCH, "OSQUERY_OS_ARCH"},
	{OSQueryFields::OSQUERY_KERNEL_VERSION, "OSQUERY_KERNEL_VERSION"},
	{OSQueryFields::OSQUERY_SYSTEM_HOSTNAME, "OSQUERY_SYSTEM_HOSTNAME"},
};


static FieldSchema createOSQuerySchema()
{
	FieldSchema schema("osquery");
	/// TODO STRING EXPORTS

	return schema;
}

OSQueryPlugin::OSQueryPlugin([[maybe_unused]]const std::string& params, FieldManager& manager)
{
	const FieldSchema schema = createOSQuerySchema();
	const FieldSchemaHandler schemaHandler = manager.registerSchema(schema);

	for (const auto& [field, name] : fields) {
		m_fieldHandlers[field] = schemaHandler.getFieldHandler(name);
	}
}

FlowAction OSQueryPlugin::onFlowCreate(FlowRecord& flowRecord, \
	[[maybe_unused]] const Packet& packet)
{
	if (const std::optional<JsonParser::AboutProgram> programInfo
			= manager.readInfoAboutProgram(flowRecord.flowKey); programInfo.has_value()) {
		//TODO FIX GLOBAL COUNTERS
		//numberOfSuccessfullyRequests++;
		m_exportData.programName = programInfo->name;
    	m_exportData.username = programInfo->username;
	}

	return FlowAction::RequestNoData;
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

ProcessPlugin* OSQueryPlugin::clone(std::byte* constructAtAddress)
{
	return std::construct_at(reinterpret_cast<OSQueryPlugin*>(constructAtAddress), std::move(*this));
}

std::string OSQueryPlugin::getName() const {
	return osqueryPluginManifest.name;
}

const void* OSQueryPlugin::getExportData() const noexcept {
	return &m_exportData;
}	

static const PluginRegistrar<OSQueryPlugin, PluginFactory<ProcessPlugin, const std::string&, FieldManager&>>
	osqueryRegistrar(osqueryPluginManifest);

} // namespace ipxp
