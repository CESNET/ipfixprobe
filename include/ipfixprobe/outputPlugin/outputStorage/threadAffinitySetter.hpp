#pragma once

#include "threadUtils.hpp"

#include <iostream>
#include <memory>
#include <vector>

#include <numa.h>

namespace ipxp::output {

class ThreadAffinitySetter {
public:
	static void setExactCoreOnNumaNode(const size_t nodeIndex)
	{
		const uint16_t threadIndex = getThreadId();
		const std::size_t numaIndex = nodeIndex % m_architectureInfo.cpusByNumaNode.size();
		const std::size_t cpuIndex
			= threadIndex % m_architectureInfo.cpusByNumaNode[numaIndex].size();
		const int cpuToBind = m_architectureInfo.cpusByNumaNode[numaIndex][cpuIndex];

		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		CPU_SET(cpuToBind, &cpuset);
		const pthread_t current_thread = pthread_self();
		const int errCode = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
		if (errCode != 0) {
			throw std::system_error(errCode, std::generic_category(), "Failed to pin thread");
		}
	}

	static void setNumaNode(const size_t nodeIndex)
	{
		const std::size_t numaIndex = nodeIndex % m_architectureInfo.cpusByNumaNode.size();
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		for (const int cpuToBind : m_architectureInfo.cpusByNumaNode[numaIndex]) {
			CPU_SET(cpuToBind, &cpuset);
		}
		const pthread_t current_thread = pthread_self();
		const int errCode = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
		if (errCode != 0) {
			throw std::system_error(errCode, std::generic_category(), "Failed to pin thread");
		}
	}

private:
	struct ArchitectureInfo {
		ArchitectureInfo()
		{
			if (numa_available() == -1) {
				cpusByNumaNode
					= {std::views::iota(0, static_cast<int>(std::thread::hardware_concurrency()))
					   | std::ranges::to<std::vector>()};
				return;
			}

			const auto deleter = [](bitmask* mask) {
				if (mask)
					numa_free_cpumask(mask);
			};
			const int maxNodes = numa_max_node();
			for (int currentNode = 0; currentNode <= maxNodes; currentNode++) {
				std::unique_ptr<bitmask, decltype(deleter)> mask(numa_allocate_cpumask(), deleter);

				if (numa_node_to_cpus(currentNode, mask.get()) != 0) {
					throw std::runtime_error(
						"Failed to get CPU mask for NUMA node " + std::to_string(currentNode));
				}
				auto cpusOfNode = std::views::iota(0, (int) mask->size)
					| std::views::filter([&](int cpuIndex) {
									  return numa_bitmask_isbitset(mask.get(), cpuIndex);
								  })
					| std::ranges::to<std::vector<int>>();
				cpusByNumaNode.push_back(std::move(cpusOfNode));
			}
		}

		std::vector<std::vector<int>> cpusByNumaNode;
	};

	static inline ArchitectureInfo m_architectureInfo;
};

} // namespace ipxp::output