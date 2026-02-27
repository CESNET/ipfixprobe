#pragma once

#include "randomWait.hpp"

#include <cstddef>
#include <iostream>
#include <optional>
#include <thread>

#include <outputStorage/outputStorageReader.hpp>
#include <outputStorage/outputStorageReaderGroup.hpp>

class DummyReader {
public:
	explicit DummyReader(
		// std::shared_ptr<ipxp::output::OutputStorage<void*>> storage,
		ipxp::output::OutputStorageReaderGroup<void*>& readerGroup,
		const bool immitateWork) noexcept
		: // m_storage(storage),
		// m_reader(readerGroup.registerReader())
		//, m_readerGroupIndex(readerGroupIndex)
		m_readerGroup(readerGroup)
		, m_immitateWork(immitateWork)
	{
	}

	std::size_t readContainers() noexcept
	{
		// m_storage.registerReader(m_readerGroupIndex);
		auto reader = m_readerGroup.registerReader();
		std::size_t readContainers {};
		while (!reader.finished()) {
			void** object = reader.read();
			if (object && readContainers++ % (1ULL << 24) == 0) {
				const std::string message = "Reader  " + std::to_string(reader.getReaderIndex())
					+ " read " + std::to_string(readContainers) + " containers so far.";
				std::cout << message << std::endl;
				// m_lastPrintTime = std::chrono::steady_clock::now();
			}
			/*if (object && ++(*object)->readTimes > 4) {
				throw std::runtime_error("Object read more times than there are reader groups.");
			}*/
		}
		return readContainers;
	}

private:
	std::shared_ptr<ipxp::output::OutputStorage<void*>> m_storage;
	// std::size_t m_readerGroupIndex;
	// ipxp::output::OutputStorageReader<void*> m_reader;
	ipxp::output::OutputStorageReaderGroup<void*>& m_readerGroup;
	bool m_immitateWork;
	// std::chrono::steady_clock::time_point m_lastPrintTime = std::chrono::steady_clock::now();
};