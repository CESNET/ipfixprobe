/**
 * @file
 * @brief Definition of NDP header format.
 * @author Pavel Siska <siska@cesnet.cz>
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstdint>

namespace ipxp {

/**
 * @brief NDP header format.
 */
struct [[gnu::packed]] NdpHeader {
	uint8_t interface : 4; //!< Interface number on which the data was captured.
	uint8_t dma_channel : 4; //!< DMA channel.
	uint8_t crc_hash : 4; //!< Precomputed CRC hash (4 bits).
	uint8_t data_type : 4; //!< Format of data that follow this header.
	uint16_t frame_size; //!< Size of captured frame.
	uint64_t timestamp; //!< Timestamp of capture.
};

} // namespace ipxp
