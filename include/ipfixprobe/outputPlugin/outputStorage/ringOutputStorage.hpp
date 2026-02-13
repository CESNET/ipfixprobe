#pragma once

#include "../../ring.h"
#include "outputStorage.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

class RingOutputStorage : public OutputStorage {
public:
	explicit RingOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage(writersCount)
		, m_ring(
			  ipx_ring_init(
				  static_cast<uint32_t>(ALLOCATION_BUFFER_CAPACITY * 32),
				  writersCount > 1),
			  &ipx_ring_destroy)
		, m_lastReadContainer(allocateNewContainer())
	{
		static_assert(sizeof(ContainerWrapper) == sizeof(void*));
	}

	bool storeContainer(
		ContainerWrapper container,
		[[maybe_unused]] const uint8_t writerId) noexcept override
	{
		if (container.empty()) {
			throw std::runtime_error("Attempt to store empty container");
		}
		ipx_ring_push(m_ring.get(), *reinterpret_cast<void**>(&container));
		return true;
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		if (!m_lastReadContainer.empty()) {
			m_lastReadContainer.deallocate(*m_allocationBuffer);
		}
		if (ipx_ring_cnt(m_ring.get()) == 0) {
			return std::nullopt;
		}

		auto pop = ipx_ring_pop(m_ring.get());
		if (pop == nullptr) {
			return std::nullopt;
		}
		ContainerWrapper& container = *reinterpret_cast<ContainerWrapper*>(&pop);
		m_lastReadContainer.assign(container, *m_allocationBuffer);
		return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
			getReferenceCounter(m_lastReadContainer));
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent();
	}

private:
	std::unique_ptr<ipx_ring_t, decltype(&ipx_ring_destroy)> m_ring;
	ContainerWrapper m_lastReadContainer;
};

} // namespace ipxp::output