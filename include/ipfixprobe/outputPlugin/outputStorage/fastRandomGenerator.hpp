#pragma once

#include <cstddef>
#include <cstdint>

namespace ipxp::output {

template<typename ResultType = uint8_t>
class FastRandomGenerator {
public:
	class FastRandomGeneratorHandler {
	public:
		ResultType getValue() noexcept
		{
			return generator.m_randomSequence[m_valueIndex++ % generator.SEQUENCE_LENGTH];
		}

	private:
		friend class FastRandomGenerator;
		explicit FastRandomGeneratorHandler(
			const uint8_t id,
			FastRandomGenerator& generator) noexcept
			: m_id(id)
			, generator(generator)
		{
		}

		std::size_t m_valueIndex {std::random_device {}() % FastRandomGenerator::SEQUENCE_LENGTH};
		const uint8_t m_id;
		FastRandomGenerator& generator;
	};

	explicit FastRandomGenerator(const ResultType lowerBound, const ResultType upperBound) noexcept
	{
		std::mt19937 generator(std::random_device {}());
		std::uniform_int_distribution<> dis(lowerBound, upperBound);
		std::ranges::for_each(m_randomSequence, [&](auto& value) {
			value = static_cast<ResultType>(dis(generator));
		});
	}

	FastRandomGeneratorHandler getHandler() noexcept
	{
		return FastRandomGeneratorHandler(m_handlerCounter++, *this);
	}

private:
	constexpr static std::size_t SEQUENCE_LENGTH = 1 << 12;
	std::array<ResultType, SEQUENCE_LENGTH> m_randomSequence;
	std::atomic<uint8_t> m_handlerCounter {0};
};

} // namespace ipxp::output