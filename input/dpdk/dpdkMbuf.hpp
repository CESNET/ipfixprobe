/**
 * \file
 * \brief Declaration of the DpdkMbuf class.
 * \author Pavel Siska <siska@cesnet.cz>
 * \date 2023
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

#include <cstdint>
#include <rte_mbuf.h>
#include <vector>

namespace ipxp {

/**
 * @brief Wrapper class for DPDK mbuf objects.
 */
class DpdkMbuf {
public:

	/**
     * @brief Constructs a DpdkMbuf object.
     * @param mBufsCount The initial size of the mbufs vector.
     */
	DpdkMbuf(size_t mBufsCount = 0);

	/**
     * @brief Releases the allocated mbufs.
     */
	~DpdkMbuf();

	/**
     * @brief Resizes the mbufs vector.
     * @param mBufsCount The new size of the mbufs vector.
     */
	void resize(size_t mBufsCount);

	/**
     * @brief Sets the number of mbufs in use.
     * @param mBufsInUse The number of mbufs currently in use.
     */
	void setMbufsInUse(size_t mBufsInUse) noexcept;

	/**
     * @brief Returns the maximum size (currently allocated) of the mbufs vector.
     * @return The maximum size of the mbufs vector.
     */
	uint16_t maxSize() const noexcept;

	/**
     * @brief Returns the current size of the mbufs vector. (in use)
     * @return The current size of the mbufs vector.
     */
	uint16_t size() const noexcept;

	/**
     * @brief Returns a pointer to the underlying mbufs data.
     * @return A pointer to the underlying mbufs data.
     */
	rte_mbuf** data();

	/**
     * @brief Releases all the mbufs.
	 * @note Function calls rte_pktmbuf_free()
     */
	void releaseMbufs();

	/**
     * @brief Overloaded subscript operator to access mbufs by index.
     * @param index The index of the mbuf to access.
     * @return The mbuf at the specified index.
     */
	rte_mbuf* operator[](int index) { return m_mBufs[index]; }

private:
	std::vector<rte_mbuf*> m_mBufs;
	uint16_t m_mBufsCount;
	uint16_t m_mBufsInUse;
};

} // namespace ipxp
