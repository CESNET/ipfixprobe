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
		ipxp::output::OutputStorage::WriteHandler writeHandler = m_storage.registerWriter();
		ipxp::FlowRecordDeleter flowRecordDeleter(16);
		for (const auto _ : std::views::iota(0u, m_containersToWrite)) {
			for (const auto _ : std::views::iota(0u, ipxp::output::OutputContainer::SIZE)) {
				ipxp::FlowRecordUniquePtr flowRecord(nullptr, flowRecordDeleter);
				writeHandler.pushFlowRecord(std::move(flowRecord));
			}
			if (m_immitateWork) {
				std::this_thread::sleep_for(std::chrono::microseconds(1));
			}
		}
		std::cout << "Writer finished writing " << std::endl;
	}

private:
	bool m_unregistered = false;
	const std::size_t m_containersToWrite;
	ipxp::output::OutputStorage& m_storage;
	bool m_immitateWork = false;
};