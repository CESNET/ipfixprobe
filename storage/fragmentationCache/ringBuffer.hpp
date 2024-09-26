/**
 * \file
 * \author Pavel Siska <siska@cesnet.cz>
 * \brief Circular ring buffer
 */
/*
 * Copyright (C) 2023 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 */

#pragma once

#include <algorithm>
#include <array>
#include <iterator>
#include <stdexcept>

namespace ipxp {

namespace detail {

template<class size_type, size_type N>
struct RingBufferIndexWrapper {
    inline static constexpr size_type increment(size_type value) noexcept
    {
        return (value + 1) % N;
    }

    inline static constexpr size_type decrement(size_type value) noexcept
    {
        return (value + N - 1) % N;
    }
};

template<class T>
constexpr typename std::conditional<
    (!std::is_nothrow_move_assignable<T>::value && std::is_copy_assignable<T>::value),
    const T&,
    T&&>::type
move_if_noexcept_assign(T& arg) noexcept
{
    return (std::move(arg));
}

template<class S, class TC, std::size_t N>
class RingBufferIterator {
public:
    using iterator_category = std::bidirectional_iterator_tag;
    using value_type = TC;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    explicit constexpr RingBufferIterator() noexcept
        : m_buf(nullptr)
        , m_pos(0)
        , m_left_in_forward(0)
    {
    }

    explicit constexpr RingBufferIterator(
        S* buf,
        std::size_t pos,
        std::size_t left_in_forward) noexcept
        : m_buf(buf)
        , m_pos(pos)
        , m_left_in_forward(left_in_forward)
    {
    }

    template<class TSnc, class Tnc>
    RingBufferIterator& operator=(const RingBufferIterator<TSnc, Tnc, N>& other) noexcept
    {
        m_buf = other.m_buf;
        m_pos = other.m_pos;
        m_left_in_forward = other.m_left_in_forward;
        return *this;
    };

    reference operator*() const noexcept { return (*m_buf)[m_pos]; }

    constexpr pointer operator->() const noexcept { return &(*m_buf)[m_pos]; }

    RingBufferIterator& operator++() noexcept
    {
        m_pos = indexWrapper::increment(m_pos);
        --m_left_in_forward;
        return *this;
    }

    RingBufferIterator& operator--() noexcept
    {
        m_pos = indexWrapper::decrement(m_pos);
        ++m_left_in_forward;
        return *this;
    }

    RingBufferIterator operator++(int) noexcept
    {
        RingBufferIterator temp = *this;
        m_pos = indexWrapper::increment(m_pos);
        --m_left_in_forward;
        return temp;
    }

    RingBufferIterator operator--(int) noexcept
    {
        RingBufferIterator temp = *this;
        m_pos = indexWrapper::decrement(m_pos);
        ++m_left_in_forward;
        return temp;
    }

    template<class Tx, class Ty>
    constexpr bool operator==(const RingBufferIterator<Tx, Ty, N>& lhs) const noexcept
    {
        return lhs.m_left_in_forward == m_left_in_forward && lhs.m_pos == m_pos
            && lhs.m_buf == m_buf;
    }

    template<typename Tx, typename Ty>
    constexpr bool operator!=(const RingBufferIterator<Tx, Ty, N>& lhs) const noexcept
    {
        return !(operator==(lhs));
    }

private:
    S* m_buf;
    std::size_t m_pos;
    std::size_t m_left_in_forward;

    using indexWrapper = detail::RingBufferIndexWrapper<std::size_t, N>;
};

} // namespace detail

/**
 * @brief A fixed-size ring buffer (circular buffer) data structure.
 *
 * This class template implements a ring buffer that holds a fixed number
 * of elements in a circular manner. It supports insertion, removal, and
 * traversal of elements through iterators.
 *
 * @tparam T The value type stored in the ring buffer.
 * @tparam N The maximum capacity of the ring buffer.
 */
template<typename T, std::size_t N>
class RingBuffer {
private:
    using storage_type = std::array<T, N>;

public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using reference = T&;
    using const_reference = const T&;
    using pointer = T*;
    using const_pointer = const T*;
    using iterator = detail::RingBufferIterator<storage_type, T, N>;
    using const_iterator = detail::RingBufferIterator<const storage_type, const T, N>;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    constexpr explicit RingBuffer()
        : m_head(1)
        , m_tail(0)
        , m_size(0)
        , m_buffer()
    {
    }

    ~RingBuffer() { clear(); }

    /// capacity
    constexpr bool empty() const noexcept { return m_size == 0; }

    constexpr bool full() const noexcept { return m_size == N; }

    constexpr size_type size() const noexcept { return m_size; }

    constexpr size_type max_size() const noexcept { return N; }

    /// element access
    reference front() noexcept { return m_buffer[m_head]; }

    constexpr const_reference front() const noexcept { return m_buffer[m_head]; }

    reference back() noexcept { return m_buffer[m_tail]; }

    constexpr const_reference back() const noexcept { return m_buffer[m_tail]; }

    pointer data() noexcept { return &m_buffer[0]; }

    constexpr const_pointer data() const noexcept { return &m_buffer[0]; }

    /// modifiers
    void push_back(const value_type& value)
    {
        size_type new_tail;
        if (full()) {
            new_tail = m_head;
            m_head = indexWrapper::increment(m_head);
            --m_size;
            m_buffer[new_tail] = detail::move_if_noexcept_assign(value);
        } else {
            new_tail = indexWrapper::increment(m_tail);
            new (&(m_buffer[new_tail])) T(std::move_if_noexcept(value));
        }

        m_tail = new_tail;
        ++m_size;
    }

    template<typename... Args>
    void emplace_back(Args&&... args)
    {
        size_type new_tail;
        if (full()) {
            new_tail = m_head;
            m_head = indexWrapper::increment(m_head);
            --m_size;
            destroy(new_tail);
        } else {
            new_tail = indexWrapper::increment(m_tail);
        }

        new (&(m_buffer[new_tail])) value_type(std::forward<Args>(args)...);
        m_tail = new_tail;
        ++m_size;
    }

    void pop_back() noexcept
    {
        size_type old_tail = m_tail;
        --m_size;
        m_tail = indexWrapper::decrement(m_tail);
        destroy(old_tail);
    }

    void clear() noexcept
    {
        while (m_size != 0) {
            pop_back();
        }

        m_head = 1;
        m_tail = 0;
    }

    /// iterators
    iterator begin() noexcept
    {
        if (empty()) {
            return end();
        }
        return iterator(&m_buffer, m_head, m_size);
    }

    const_iterator begin() const noexcept
    {
        if (empty()) {
            return end();
        }
        return const_iterator(&m_buffer, m_head, m_size);
    }

    const_iterator cbegin() const noexcept
    {
        if (empty()) {
            return cend();
        }
        return const_iterator(&m_buffer, m_head, m_size);
    }

    reverse_iterator rbegin() noexcept
    {
        if (empty()) {
            return rend();
        }

        return reverse_iterator(iterator(&m_buffer, indexWrapper::increment(m_tail), 0));
    }

    const_reverse_iterator rbegin() const noexcept
    {
        if (empty()) {
            return rend();
        }
        return const_reverse_iterator(
            const_iterator(&m_buffer, indexWrapper::increment(m_tail), 0));
    }

    const_reverse_iterator crbegin() const noexcept
    {
        if (empty()) {
            return crend();
        }
        return const_reverse_iterator(
            const_iterator(&m_buffer, indexWrapper::increment(m_tail), 0));
    }

    iterator end() noexcept { return iterator(&m_buffer, indexWrapper::increment(m_tail), 0); }

    const_iterator end() const noexcept
    {
        return const_iterator(&m_buffer, indexWrapper::increment(m_tail), 0);
    }

    const_iterator cend() const noexcept
    {
        return const_iterator(&m_buffer, indexWrapper::increment(m_tail), 0);
    }

    reverse_iterator rend() noexcept
    {
        return reverse_iterator(iterator(&m_buffer, m_head, m_size));
    }

    const_reverse_iterator rend() const noexcept
    {
        return const_reverse_iterator(const_iterator(&m_buffer, m_head, m_size));
    }

    const_reverse_iterator crend() const noexcept
    {
        return const_reverse_iterator(const_iterator(&m_buffer, m_head, m_size));
    }

private:
    using indexWrapper = detail::RingBufferIndexWrapper<size_type, N>;

    inline void destroy(size_type idx) noexcept { m_buffer[idx].~T(); }

    size_type m_head;
    size_type m_tail;
    size_type m_size;
    storage_type m_buffer;
};

} // namespace ipxp
