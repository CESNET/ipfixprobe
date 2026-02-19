#pragma once

#include "randomWait.hpp"

#include <cstddef>
#include <iostream>
#include <optional>
#include <thread>

#include <outputStorage/outputStorage.hpp>

class DummyReader {
public:
	explicit DummyReader(
		ipxp::output::OutputStorage<ipxp::output::OutputContainer>& storage,
		ipxp::output::OutputStorage<ipxp::output::OutputContainer>::ReaderGroupHandler&
			readerGroupHandler,
		const bool immitateWork) noexcept
		: m_storage(storage)
		, m_readerGroupHandler(readerGroupHandler)
		//, m_readerGroupIndex(readerGroupIndex)
		, m_immitateWork(immitateWork)
	{
	}

	std::size_t readContainers() noexcept
	{
		// m_storage.registerReader(m_readerGroupIndex);
		std::size_t readContainers {};
		ipxp::output::OutputStorage<ipxp::output::OutputContainer>::ReadHandler readHandler
			= m_readerGroupHandler.getReaderHandler();
		while (!readHandler.finished()) {
			ipxp::output::OutputContainer* container = readHandler.read();
			if (container && readContainers++ % (1ULL << 24) == 0) {
				const std::string message = "Reader  "
					+ std::to_string(readHandler.getReaderIndex()) + " read "
					+ std::to_string(readContainers) + " containers so far.";
				std::cout << message << std::endl;
				// m_lastPrintTime = std::chrono::steady_clock::now();
			}
			if (container && ++container->readTimes > 4) {
				throw std::runtime_error("Container read more times than there are reader groups.");
			}
		}
		return readContainers;
	}

private:
	ipxp::output::OutputStorage<ipxp::output::OutputContainer>& m_storage;
	// std::size_t m_readerGroupIndex;
	ipxp::output::OutputStorage<ipxp::output::OutputContainer>::ReaderGroupHandler&
		m_readerGroupHandler;
	bool m_immitateWork;
	// std::chrono::steady_clock::time_point m_lastPrintTime = std::chrono::steady_clock::now();
};