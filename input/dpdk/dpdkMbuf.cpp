/**
 * \file
 * \brief Implementation of the DpdkMbuf class.
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

#include "dpdkMbuf.hpp"

namespace ipxp {

DpdkMbuf::DpdkMbuf(size_t mBufsCount)
	: m_mBufsCount(mBufsCount)
	, m_mBufsInUse(0)
{
	m_mBufs.resize(mBufsCount);
}

void DpdkMbuf::resize(size_t mBufsCount)
{
	releaseMbufs();
	m_mBufs.resize(mBufsCount);
	m_mBufsCount = mBufsCount;
}

void DpdkMbuf::setMbufsInUse(size_t mBufsInUse) noexcept
{
	m_mBufsInUse = mBufsInUse;
}

DpdkMbuf::~DpdkMbuf()
{
	releaseMbufs();
}

uint16_t DpdkMbuf::maxSize() const noexcept
{
	return m_mBufsCount;
}

uint16_t DpdkMbuf::size() const noexcept
{
	return m_mBufsInUse;
}

rte_mbuf** DpdkMbuf::data()
{
	return m_mBufs.data();
}

void DpdkMbuf::releaseMbufs()
{
	for (auto mBufID = 0; mBufID < m_mBufsInUse; mBufID++) {
		rte_pktmbuf_free(m_mBufs[mBufID]);
	}
	m_mBufsInUse = 0;
}

} // namespace ipxp