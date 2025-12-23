#pragma once

#include "flowKey.hpp"
#include "flowRecord.hpp"
#include "ipAddress.hpp"
#include "processPluginEntry.hpp"
// #include "processPluginBuilder.hpp"

#include <cstddef>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>
#include <vector>

namespace ipxp::process {

static std::size_t calculatePluginTableSize(const std::vector<ProcessPluginEntry>& plugins) noexcept
{
	return sizeof(FlowRecordPluginTable) + ((plugins.size() - 1) * sizeof(PluginLayoutItem));
}

class FlowRecordBuilder {
public:
	FlowRecordBuilder(
		const std::vector<ProcessPluginEntry>& plugins,
		const FlowKeyLayout& flowKeyLayout)
		: m_processPluginEntries(plugins)
		, m_flowKeyLayout(flowKeyLayout)
	{
		prepareLayout();
	}

	std::size_t getTotalBufferSize() const { return m_totalBufferSize; }
	std::size_t getMaxAlignment() const { return m_maxAlignment; }
	FlowRecordLayout getLayout() const { return m_layout; }

	void printLayoutInfo() const
	{
		std::cout << "FlowKey:\n";
		std::cout << "  Size:      " << m_flowKeyLayout.size << " bytes\n";
		std::cout << "  Alignment: " << m_flowKeyLayout.alignment << " bytes\n";
		std::cout << "  Offset:    " << m_layout.flowKeyOffset << "\n\n";

		std::cout << "Plugin Table:\n";
		std::cout << "  Offset:    " << m_layout.pluginTableOffset << "\n";
		std::cout << "  Size:      " << calculatePluginTableSize(m_processPluginEntries)
				  << " bytes\n";
		std::cout << "  Count:     " << m_processPluginEntries.size() << "\n\n";

		std::cout << "Plugins (" << m_processPluginEntries.size() << "):\n";
		for (std::size_t i = 0; i < m_pluginLayouts.size(); ++i) {
			const auto& layout = m_pluginLayouts[i];
			if (layout.offset == std::numeric_limits<std::size_t>::max()) {
				std::cout << "  Plugin " << i << ": disabled\n";
			} else {
				const auto& pluginEntry = m_processPluginEntries[i];
				std::cout << "  Plugin " << i << ": " << pluginEntry.name << "\n"; // přidáno jméno
				std::cout << "    Offset:    " << layout.offset << "\n";
				std::cout << "    Context Size:      " << pluginEntry.contextSize << " bytes\n";
				std::cout << "    Context Alignment: " << pluginEntry.contextAlignment
						  << " bytes\n";
			}
		}

		std::cout << "\nTotal FlowRecord size: " << m_totalBufferSize << " bytes\n";
		std::cout << "Max alignment:     " << m_maxAlignment << " bytes\n";
	}

	FlowRecordUniquePtr build()
	{
		// Alokace zarovnané paměti
		void* rawMem = ::operator new(m_totalBufferSize, std::align_val_t(m_maxAlignment));

		// Konstrukce FlowRecord přímo v alokované paměti (placement new)
		FlowRecord* recordPtr
			= std::construct_at(static_cast<FlowRecord*>(rawMem), m_pluginsAvailable);

		recordPtr->m_layout = m_layout;

		// Inicializace pluginové tabulky
		FlowRecordPluginTable* pluginTable = reinterpret_cast<FlowRecordPluginTable*>(
			reinterpret_cast<std::byte*>(rawMem) + m_layout.pluginTableOffset);
		pluginTable->pluginCount = m_pluginLayouts.size();
		for (std::size_t i = 0; i < m_pluginLayouts.size(); ++i) {
			pluginTable->pluginDataLayouts[i] = m_pluginLayouts[i];
		}

		return FlowRecordUniquePtr(recordPtr, FlowRecordDeleter {m_maxAlignment});
	}

private:
	void prepareLayout()
	{
		constexpr std::size_t baseSize = sizeof(FlowRecord);
		m_maxAlignment = alignof(FlowRecord);

		std::size_t flowKeyOffset = alignUp(baseSize, m_flowKeyLayout.alignment);

		std::size_t pluginTableOffset
			= alignUp(flowKeyOffset + m_flowKeyLayout.size, alignof(FlowRecordPluginTable));

		std::size_t pluginTableSize = calculatePluginTableSize(m_processPluginEntries);

		std::size_t currentOffset = pluginTableOffset + pluginTableSize;

		m_maxAlignment = std::max(m_maxAlignment, m_flowKeyLayout.alignment);
		m_maxAlignment = std::max(m_maxAlignment, alignof(FlowRecordPluginTable));

		m_pluginLayouts.clear();
		m_pluginsAvailable.reset();

		for (std::size_t pluginID = 0; pluginID < m_processPluginEntries.size(); ++pluginID) {
			const auto& pluginEntry = m_processPluginEntries[pluginID];
			/*if (!pluginEntry.enabled) {
				m_pluginLayouts.push_back({std::numeric_limits<std::size_t>::max()});
				continue;
			}*/

			std::size_t alignment = pluginEntry.contextAlignment;
			if (alignment > 1) {
				std::size_t mod = currentOffset % alignment;
				if (mod != 0) {
					currentOffset += alignment - mod;
				}
			}

			m_pluginLayouts.push_back({currentOffset});
			m_pluginsAvailable.set(pluginID);

			currentOffset += pluginEntry.contextSize;
			m_maxAlignment = std::max(m_maxAlignment, alignment);
		}

		m_totalBufferSize = currentOffset;

		m_layout.flowKeyOffset = flowKeyOffset;
		m_layout.pluginTableOffset = pluginTableOffset;
	}

	static std::size_t alignUp(std::size_t value, std::size_t alignment)
	{
		return (value + alignment - 1) & ~(alignment - 1);
	}

private:
	std::vector<ProcessPluginEntry> m_processPluginEntries;
	FlowKeyLayout m_flowKeyLayout;

	std::vector<PluginLayoutItem> m_pluginLayouts;
	PluginsBitset m_pluginsAvailable = {};

	std::size_t m_totalBufferSize = 0;
	std::size_t m_maxAlignment = 0;
	FlowRecordLayout m_layout;
};

} // namespace ipxp