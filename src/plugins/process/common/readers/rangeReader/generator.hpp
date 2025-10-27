/**
 * @file
 * @brief Provides a generator utility for creating parsing ranges.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <ranges>

namespace ipxp {

/**
 * @class Generator
 * @brief A range generator that produces values on-the-fly using a callable.
 *
 * This class template implements a range that generates values by repeatedly
 * invoking a provided callable until it returns `std::nullopt`. It conforms
 * to the C++ ranges library concepts.
 *
 * @tparam Callable A callable type that returns `std::optional<T>` when invoked.
 */
template<typename Callable>
class Generator : public std::ranges::view_interface<Generator<Callable>> {
	using ReturnType = std::invoke_result_t<Callable>;

public:
	using value_type = typename ReturnType::value_type;
	using iterator = struct Iterator;

	Generator(Callable callable)
		: m_callable(std::move(callable))
	{
	}

	Generator& operator=(const Generator& other) noexcept
	{
		m_callable = other.m_callable;
		return *this;
	}

	class Iterator {
		Callable* callable = nullptr;
		ReturnType value = std::nullopt;
		bool noMoreValues = false;

	public:
		using iterator_category = std::input_iterator_tag;
		using value_type = typename ReturnType::value_type;
		using difference_type = std::ptrdiff_t;

		Iterator()
			: callable(nullptr)
			, noMoreValues(true)
		{
		}

		Iterator(Callable* callable)
			: callable(callable)
		{
			++(*this);
		}

		auto operator*() const -> value_type { return *value; }

		Iterator& operator++()
		{
			if (callable && !noMoreValues) {
				value = (*callable)();
				if (!value.has_value()) {
					noMoreValues = true;
				}
			}
			return *this;
		}

		Iterator& operator++(int) { return ++(*this); }

		bool operator==(const Iterator& other) const { return noMoreValues == other.noMoreValues; }
		bool operator!=(const Iterator& other) const { return !(*this == other); }
	};

	Iterator begin() { return Iterator(&m_callable); }

	Iterator end() { return {}; }

private:
	Callable m_callable;
};

template<typename Callable>
Generator(Callable) -> Generator<Callable>;

} // namespace ipxp

template<typename Callable>
inline constexpr bool std::ranges::enable_borrowed_range<ipxp::Generator<Callable>> = true;

namespace ipxp::generator::test {

inline constexpr auto testCallable = []() -> std::optional<int> { return std::nullopt; };

static_assert(std::is_same_v<
			  decltype(std::ranges::begin(std::declval<Generator<decltype(testCallable)>>())),
			  typename Generator<decltype(testCallable)>::Iterator>);

static_assert(std::is_same_v<
			  decltype(std::ranges::end(std::declval<Generator<decltype(testCallable)>>())),
			  typename Generator<decltype(testCallable)>::Iterator>);

static_assert(
	std::ranges::range<Generator<decltype(testCallable)>>,
	"Generator must satisfy the range concept");
static_assert(
	std::ranges::input_range<Generator<decltype(testCallable)>>,
	"Generator must be an input range");
static_assert(
	std::ranges::viewable_range<Generator<decltype(testCallable)>>,
	"Generator must be viewable");

using It = decltype(std::ranges::begin(std::declval<Generator<decltype(testCallable)>&>()));
static_assert(std::input_iterator<It>, "Generator's iterator must satisfy input_iterator");

} // namespace ipxp::generator::test
