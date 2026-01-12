#pragma once

#include "randomWait.hpp"

#include <cstddef>
#include <iostream>
#include <ranges>
#include <thread>

#include <outputStorage/outputStorage.hpp>

class DummyWriter {
public:
	explicit DummyWriter(
		const std::size_t containersToWrite,
		ipxp::output::OutputStorage& storage,
		const bool immitateWork) noexcept
		: m_containersToWrite(containersToWrite)
		, m_storage(storage)
		, m_immitateWork(immitateWork)
	{
	}

	DummyWriter(const DummyWriter& other) noexcept
		: m_containersToWrite(other.m_containersToWrite)
		, m_storage(other.m_storage)
		, m_immitateWork(other.m_immitateWork)
	{
	}

	void writeContainers() noexcept
	{
		for (const auto _ : std::views::iota(0u, m_containersToWrite)) {
			if (m_immitateWork) {
				std::this_thread::sleep_for(std::chrono::microseconds(1));
			}
			ipxp::output::ContainerWrapper container = m_storage.allocateNewContainer();
			if (container.empty()) {
				throw std::runtime_error("Failed to allocate new container in DummyWriter");
			}
			container.getContainer().creationTime = std::chrono::steady_clock::now();
			container.getContainer().sequenceNumber
				= ipxp::output::OutputContainer::globalSequenceNumber++;
			container.getContainer().readTimes = 0;
			randomWait();
			m_storage.storeContainer(std::move(container));
		}
		std::cout << "Writer finished writing " << std::endl;
		m_storage.unregisterWriter();
	}

private:
	bool m_unregistered = false;
	const std::size_t m_containersToWrite;
	ipxp::output::OutputStorage& m_storage;
	bool m_immitateWork = false;
};