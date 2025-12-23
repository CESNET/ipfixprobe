#pragma once

#include "../api.hpp"
#include "../pluginFactory/pluginFactory.hpp"
#include "fieldManager.hpp"
#include "flowKey.hpp"
#include "flowRecord.hpp"
#include "flowRecordBuilder.hpp"
#include "processPlugin.hpp"
#include "processPluginEntry.hpp"

namespace ipxp::process {

class IPXP_API ProcessPluginManager {
public:
	ProcessPluginManager(FieldManager& manager)
		: m_fieldManager(manager)
	{
	}

	template<typename... Args>
	void addProcessPlugin(const std::string& pluginName, Args&&... args)
	{
		std::lock_guard<std::mutex> lock(m_mutex);

		auto& processPluginFactory = ProcessPluginFactory::getInstance();
		// const int pluginID = ProcessPluginIDGenerator::instance().generatePluginID();
		auto processPlugin = processPluginFactory.createShared(
			pluginName,
			std::forward<Args>(args)...,
			m_fieldManager);

		auto [pluginContextSize, pluginContextAlignment] = processPlugin->getDataMemoryLayout();
		const ProcessPluginEntry pluginEntry = {
			.name = pluginName,
			.contextSize = pluginContextSize,
			.contextAlignment = pluginContextAlignment,
			//.enabled = true,
			.plugin = std::move(processPlugin),
		};

		printPluginEntry(pluginEntry);

		m_processPlugins.emplace_back(pluginEntry);
	}

	void enableProcessPlugin(const std::string& pluginName)
	{
		std::lock_guard<std::mutex> lock(m_mutex);

		for (auto& plugin : m_processPlugins) {
			if (plugin.name == pluginName) {
				// plugin.enabled = true;
				std::cout << "Plugin '" << pluginName << "' has been enabled\n";
				return;
			}
		}
		std::cout << "Plugin '" << pluginName << "' not found\n";
	}

	void disableProcessPlugin(const std::string& pluginName)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		for (auto& plugin : m_processPlugins) {
			if (plugin.name == pluginName) {
				// plugin.enabled = false;
				std::cout << "Plugin '" << pluginName << "' has been disabled\n";
				return;
			}
		}
		std::cout << "Plugin '" << pluginName << "' not found\n";
	}

	void processFlowRecord(FlowContext& flowContext)
	{
		// updateBasicStats

		FlowRecord& flowRecord = flowContext.flowRecord;

		for (std::size_t pluginID = 0; pluginID < m_processPlugins.size(); pluginID++) {
			const auto& pluginEntry = m_processPlugins[pluginID];
			// Plugin is not available in FlowRecord
			if (!flowRecord.pluginsAvailable.test(pluginID)) {
				continue;
			}

			// Plugin does not want to process packets
			if (!flowRecord.pluginsUpdate.test(pluginID)) {
				continue;
			}

			// Call beforeUpdate for constructed plugins
			if (flowRecord.pluginsConstructed.test(pluginID)) {
				const auto pluginUpdateResult = pluginEntry.plugin->beforeUpdate(
					flowContext,
					flowRecord.getPluginContext(pluginID));

				// TODO return value check
			}
		}

		for (std::size_t pluginID = 0; pluginID < m_processPlugins.size(); pluginID++) {
			const auto& pluginEntry = m_processPlugins[pluginID];
			// Plugin is not available in FlowRecord
			if (!flowRecord.pluginsAvailable.test(pluginID)) {
				continue;
			}

			// Plugin does not want to process packets
			if (!flowRecord.pluginsUpdate.test(pluginID)) {
				continue;
			}

			// Plugin not yet constructed, call onInit
			if (!flowRecord.pluginsConstructed.test(pluginID)) {
				const auto pluginInitResult = pluginEntry.plugin->onInit(
					flowContext,
					flowRecord.getPluginContext(pluginID));

				// If no update is needed, we can reset the update flag
				/*if (pluginInitResult.updateRequirement == UpdateRequirement::NoUpdateNeeded) {
					flowRecord.pluginsUpdate.reset(pluginID);
				}

				// TODO: je toto valid?
				if (pluginInitResult.flowAction == FlowAction::RemovePlugin) {
					throw std::runtime_error("Invalid plugin state");
					// flowRecord.pluginsAvailable.reset(pluginID);
				}

				// If the plugin was successfully constructed, we set the constructed bit
				if (pluginInitResult.constructionState == ConstructionState::Constructed) {
					flowRecord.pluginsConstructed.set(pluginID);
				}*/

				continue;
			}

			// Call onUpdate for constructed plugins
			if (flowRecord.pluginsConstructed.test(pluginID)) {
				const auto pluginUpdateResult = pluginEntry.plugin->onUpdate(
					flowContext,
					flowRecord.getPluginContext(pluginID));

				// If no update is needed, we can reset the update flag
				/*if (pluginUpdateResult.updateRequirement == UpdateRequirement::NoUpdateNeeded) {
					flowRecord.pluginsUpdate.reset(pluginID);
				}

				// If the plugin requested to be removed, we reset the available bit
				if (pluginUpdateResult.flowAction == FlowAction::RemovePlugin) {
					// call onDestroy
					pluginEntry.plugin->onDestroy(flowRecord.getPluginContext(pluginID));
					flowRecord.pluginsUpdate.reset(pluginID);
					flowRecord.pluginsConstructed.reset(pluginID);
				} else if (pluginUpdateResult.flowAction == FlowAction::Flush) {
					// TODO remove flush
				}*/
			}
		}
	}

#if 0

		void exportFlowRecord(FlowRecord & flowRecord)
		{
			for (std::size_t pluginID = 0; pluginID < m_processPlugins.size(); pluginID++) {
				const auto& pluginEntry = m_processPlugins[pluginID];
				// Check if the plugin is available for the flow
				if (!flowRecord.pluginsAvailable.test(pluginID)) {
					continue;
				}

				// Check if the plugin is constructed
				if (!flowRecord.pluginsConstructed.test(pluginID)) {
					continue;
				}

				// Call the plugin's onExport method
				const auto pluginExportResult
					= pluginEntry.plugin->onExport(flowRecord, flowRecord.getPluginData(pluginID));

				// Check the export result wants to remove the plugin
				if (pluginExportResult.flowAction == FlowAction::RemovePlugin) {
					// call onDestroy
					pluginEntry.plugin->onDestroy(flowRecord.getPluginData(pluginID));

					flowRecord.pluginsAvailable.reset(pluginID);
					flowRecord.pluginsConstructed.reset(pluginID);
					flowRecord.pluginsUpdate.reset(pluginID);
				}
			}
		}
#endif

	std::shared_ptr<FlowRecordBuilder> rebuild()
	{
		auto builder = std::make_shared<FlowRecordBuilder>(m_processPlugins, FlowKey::getLayout());
		return builder;
	}

	const std::vector<ProcessPluginEntry>& getEntries() { return m_processPlugins; }

	const FieldManager& getFieldManager() const noexcept { return m_fieldManager; }

private:
	void printPluginEntry(const ProcessPluginEntry& entry)
	{
		std::cout << "Plugin: " << entry.name << "\n";
		std::cout << "  Context Size: " << entry.contextSize << " bytes\n";
		std::cout << "  Context Alignment: " << entry.contextAlignment << " bytes\n";
		// std::cout << "  Enabled: " << std::boolalpha << entry.isEnabled << "\n";
	}

	std::mutex m_mutex;
	std::atomic<std::size_t> m_pluginID = 0;
	FieldManager& m_fieldManager;
	std::vector<ProcessPluginEntry> m_processPlugins;
};

} // namespace ipxp::process
