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
		ipxp::output::OutputStorage& storage,
		ipxp::output::OutputStorage::ReaderGroupHandler& readerGroupHandler,
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
		std::size_t printCounter{};
		ipxp::output::OutputStorage::ReadHandler readHandler
			= m_readerGroupHandler.getReaderHandler();
		while (!readHandler.finished()) {
			while (readHandler.getFlowRecord() != nullptr) {
				if (printCounter++ % (1ULL << 23) == 0) {
					const std::string message = "Reader  "
						+ std::to_string(readHandler.getReaderIndex()) + " read "
						+ std::to_string(readHandler.readContainers()) + " containers so far.";
					std::cout << message << std::endl;
					// m_lastPrintTime = std::chrono::steady_clock::now();
				}
			}
		}
		return readHandler.readContainers();
	}

private:
	ipxp::output::OutputStorage& m_storage;
	// std::size_t m_readerGroupIndex;
	ipxp::output::OutputStorage::ReaderGroupHandler& m_readerGroupHandler;
	bool m_immitateWork;
	//std::chrono::steady_clock::time_point m_lastPrintTime = std::chrono::steady_clock::now();
};