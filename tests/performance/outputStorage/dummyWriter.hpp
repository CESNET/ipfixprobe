#pragma once

#include "randomWait.hpp"

#include <cstddef>
#include <iostream>
#include <ranges>
#include <thread>

#include <outputStorage/outputStorageRegistrar.hpp>
#include <outputStorage/outputStorageWriter.hpp>

template<typename StorageType>
class DummyWriter {
public:
	explicit DummyWriter(
		const std::size_t containersToWrite,
		ipxp::output::OutputStorageRegistrar<StorageType>& storageRegistrar,
		const bool immitateWork) noexcept
		: m_containersToWrite(containersToWrite)
		, m_storageRegistrar(storageRegistrar)
		, m_immitateWork(immitateWork)
	{
	}

	DummyWriter(const DummyWriter& other) noexcept
		: m_containersToWrite(other.m_containersToWrite)
		, m_storageRegistrar(other.m_storageRegistrar)
		, m_immitateWork(other.m_immitateWork)
	{
	}

	void writeContainers() noexcept
	{
		ipxp::output::OutputStorageWriter<void*> writer(m_storageRegistrar.registerWriter());
		for (const auto _ : std::views::iota(0u, m_containersToWrite)) {
			// ipxp::output::OutputContainer* container = m_writer.allocate();
			writer.push(nullptr);
		}
		std::cout << "Writer finished writing " << m_containersToWrite << " containers."
				  << std::endl;
	}

private:
	bool m_unregistered = false;
	const std::size_t m_containersToWrite;
	ipxp::output::OutputStorageRegistrar<StorageType>& m_storageRegistrar;
	// ipxp::output::OutputStorage<ipxp::output::OutputContainer>& m_storage;
	bool m_immitateWork = false;
};