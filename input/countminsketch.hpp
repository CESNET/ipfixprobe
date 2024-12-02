/**
* \file countminsketch.hpp
* \brief Template class implementing Count-Min Sketch algorithm.
 * Used to estimate frequency of events in a stream and effectively find top-k frequent events.
* \author Damir Zainullin <zaidamilda@gmail.com>
* \date 2024
*/
#pragma once

#include <array>
#include <cmath>
#include <functional>
#include <limits>
#include <queue>
#include <unordered_map>
#include <cstdint>

namespace ipxp {

/**
 * @brief Template class implementing Count-Min Sketch algorithm.
 * Used to estimate frequency of events in a stream and effectively find top-k frequent events.
 * @tparam EventType Type of tracked event event.
 * @tparam HashFunctionsCount Count of passed hash functions.
 * @tparam TopEventsCount Count of top frequent events to store.
 * @tparam RelativeError Relative error of the algorithm on scale from 1 to 9999, where 1 is the highest precision.
 * Lower error leads to higher memory consumption.
 * @tparam EventsEqual Function object to compare events.
 */
template<typename EventType, size_t HashFunctionsCount, size_t TopEventsCount = 10,
         size_t RelativeError = 100, typename EventsEqual = std::equal_to<EventType>>
class CountMinSketch {
    struct EventCount {
        EventType event;
        size_t frequency;
    };

    constexpr const static inline size_t MOST_FREQUENT_EVENTS_COUNT = TopEventsCount * 5;
public:
    /** @brief Length of row for each hash function in table. */
    constexpr const static inline size_t ROW_LENGTH = std::ceil( std::exp(1.0) / (RelativeError / 10000.0));

    /**
     * @brief Constructor.
     * @param hash_functions Array of hash functions to use.
     */
    CountMinSketch(std::array<std::function<size_t(const EventType&)>, HashFunctionsCount>
                       hash_functions) noexcept
    : m_hash_functions(std::move(hash_functions))
    , m_minimal_heap(
          [](const EventCount& a, const EventCount& b) { return a.frequency > b.frequency; })
    , m_in_heap(0, m_hash_functions[0], EventsEqual())
    {
        static_assert(TopEventsCount > 0, "TopEventsCount must be greater than 0");
        static_assert(
            RelativeError > 0 && RelativeError < 10000,
            "RelativeError must be between 0 and 10000");
        static_assert(HashFunctionsCount > 0, "HashFunctionsCount must be greater than 0");

        for (auto& row : m_event_counts) {
            row.fill(0);
        }
    }

    /**
     * @brief Insert event into the sketch.
     * @param event Event to insert.
     */
    void insert(const EventType& event) noexcept
    {
        size_t event_frequency = std::numeric_limits<size_t>::max();
        for (size_t hash_function_index = 0; hash_function_index < HashFunctionsCount;
             hash_function_index++) {
            const uint16_t event_index = get_event_index(hash_function_index, event);
            m_event_counts[hash_function_index][event_index]++;
            event_frequency = std::min(
                event_frequency,
                m_event_counts[hash_function_index][event_index]);
        }

        update_least_freq_event();

        if (m_in_heap.find(event) != m_in_heap.end()) {
            m_in_heap[event] = event_frequency;
            return;
        }

        if (m_minimal_heap.size() < MOST_FREQUENT_EVENTS_COUNT) {
            m_minimal_heap.push({event, event_frequency});
            m_in_heap[event] = event_frequency;
            return;
        }

        if (event_frequency > m_minimal_heap.top().frequency) {
            m_in_heap.erase(m_minimal_heap.top().event);
            m_minimal_heap.pop();
            m_minimal_heap.push({event, event_frequency});
            m_in_heap[event] = event_frequency;
        }
    }

    /**
     * @brief Function to get current most frequent events.
     * @return Pair of array of top frequent events and its real size.
     */
    std::pair<std::array<EventCount, TopEventsCount>, uint16_t> get_top_events() const noexcept
    {
      std::array<EventCount, MOST_FREQUENT_EVENTS_COUNT> top_events{};
      std::transform(m_in_heap.begin(), m_in_heap.end(), top_events.begin(),
         [](const std::pair<EventType, size_t>& event_count) -> EventCount {
             return {event_count.first, event_count.second};
      });
      const uint16_t inserted = std::min(m_in_heap.size(), TopEventsCount);
      std::partial_sort(top_events.begin(), top_events.begin() + inserted, top_events.end(),
                [](const EventCount& a, const EventCount& b) {
                    return a.frequency > b.frequency || ( a.frequency == b.frequency && a.event < b.event); });
      std::array<EventCount, TopEventsCount> res{};
      std::copy_n(top_events.begin(), inserted, res.begin());
      return {res, inserted};
    }
private:
    size_t get_event_index(uint16_t hash_function_index, EventType event) const noexcept
    {
        return m_hash_functions[hash_function_index](event) % ROW_LENGTH;
    }

    void update_least_freq_event() noexcept
    {
        if (m_minimal_heap.empty()) {
            return;
        }

        const EventType event = m_minimal_heap.top().event;
        const size_t new_frequency = m_in_heap[m_minimal_heap.top().event];
        m_minimal_heap.pop();
        m_minimal_heap.push({event, new_frequency});
    }

    std::array<std::array<size_t, ROW_LENGTH>, HashFunctionsCount> m_event_counts;
    std::array<std::function<size_t(const EventType&)>, HashFunctionsCount> m_hash_functions;
    std::priority_queue<EventCount, std::vector<EventCount>,
                        std::function<bool(const EventCount&, const EventCount&)>> m_minimal_heap;
    std::unordered_map<EventType, size_t, std::function<size_t(const EventType&)>,
                       std::function<bool(const EventType&,const EventType&)>> m_in_heap;
};

} // namespace ipxp