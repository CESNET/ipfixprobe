#pragma once

#include "../../ring.h"
#include "outputStorage.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

template<typename ElementType>
class RingOutputStorage : public OutputStorage<ElementType> {
public:
	explicit RingOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage<ElementType>(writersCount)
		, m_ring(
			  ipx_ring_init(
				  static_cast<uint32_t>(OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY),
				  writersCount > 1),
			  &ipx_ring_destroy)
	{
	}

	bool write(ElementType* element, [[maybe_unused]] const uint8_t writerId) noexcept override
	{
		ipx_ring_push(m_ring.get(), element);
		return true;
	}

	ElementType* read(
		[[maybe_unused]] const std::size_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		if (m_lastReadContainer != nullptr) {
			this->m_allocationBuffer->deallocate(m_lastReadContainer, 0);
			m_lastReadContainer = nullptr;
		}
		if (ipx_ring_cnt(m_ring.get()) == 0) {
			return nullptr;
		}

		auto pop = ipx_ring_pop(m_ring.get());
		if (pop == nullptr) {
			return nullptr;
		}
		ElementType* element = reinterpret_cast<ElementType*>(pop);
		m_lastReadContainer = element;
		return m_lastReadContainer;
	}

	bool finished([[maybe_unused]] const std::size_t readerGroupIndex) noexcept override
	{
		return !this->writersPresent() && ipx_ring_cnt(m_ring.get()) == 0;
	}

private:
	std::unique_ptr<ipx_ring_t, decltype(&ipx_ring_destroy)> m_ring;
	ElementType* m_lastReadContainer {nullptr};
};

} // namespace ipxp::output