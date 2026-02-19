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
		ipxp::output::OutputStorage<ipxp::output::OutputContainer>& storage,
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
		ipxp::output::OutputStorage<ipxp::output::OutputContainer>::WriteHandler writeHandler
			= m_storage.registerWriter();
		for (const auto _ : std::views::iota(0u, m_containersToWrite)) {
			ipxp::output::OutputContainer* container = writeHandler.allocate();
			writeHandler.write(container);
		}
		std::cout << "Writer finished writing " << std::endl;
	}

private:
	bool m_unregistered = false;
	const std::size_t m_containersToWrite;
	ipxp::output::OutputStorage<ipxp::output::OutputContainer>& m_storage;
	bool m_immitateWork = false;
};