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
		std::size_t readerGroupIndex,
		const bool immitateWork) noexcept
		: m_storage(storage)
		, m_readerGroupIndex(readerGroupIndex)
		, m_immitateWork(immitateWork)
	{
	}

	std::size_t readContainers() noexcept
	{
		m_storage.registerReader(m_readerGroupIndex);
		std::size_t readContainers = 0;
		uint64_t lastContainerSequenceNumber = 0;
		while (!m_storage.finished(m_readerGroupIndex)) {
			randomWait();
			std::optional<ReferenceCounterHandler<ipxp::output::OutputContainer>> containerHandler
				= m_storage.getContainer(m_readerGroupIndex);
			if (containerHandler.has_value()) {
				++readContainers;
				if (containerHandler->getData().readTimes++ > 2) {
					throw std::runtime_error(
						"Container read more times than there are reader groups.");
				}
				/*if (containerHandler->getData().sequenceNumber < lastContainerSequenceNumber) {
					throw std::runtime_error(
						"Reader read containers out of order. Last: "
						+ std::to_string(lastContainerSequenceNumber) + ", current: "
						+ std::to_string(containerHandler->getData().sequenceNumber));
				}*/
				lastContainerSequenceNumber = containerHandler->getData().sequenceNumber;
				if (m_immitateWork) {
					std::this_thread::sleep_for(std::chrono::microseconds(1));
				}
			}
			if (std::chrono::steady_clock::now() - m_lastPrintTime > std::chrono::seconds(10)) {
				const std::string message = "Reader group " + std::to_string(m_readerGroupIndex)
					+ " read " + std::to_string(readContainers) + " containers so far.";
				std::cout << message << std::endl;
				m_lastPrintTime = std::chrono::steady_clock::now();
			}
		}
		return readContainers;
	}

private:
	ipxp::output::OutputStorage& m_storage;
	std::size_t m_readerGroupIndex;
	bool m_immitateWork;
	std::chrono::steady_clock::time_point m_lastPrintTime = std::chrono::steady_clock::now();
};