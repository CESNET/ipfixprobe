/**
 * \file src/core/ring.h
 * \author Lukas Hutak <lukas.hutak@cesnet.cz>
 * \brief Ring buffer for messages (header file)
 * \date 2018
 */

/* Copyright (C) 2018 CESNET, z.s.p.o.
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
 *
 *
 *
 */

#ifndef IPX_RING_H
#define IPX_RING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define IPX_API __attribute__((visibility("default")))

typedef void ipx_msg_t;

/**
 * \defgroup ipx_ring Message ring buffer
 *
 * \brief Ring buffer for passing IPFIXcol messages
 *
 * The ring buffer provides Multi Producer Single Consumer queue for passing the messages
 * from one or more produces to a single reader. The ring buffer is supposed to be used as a part
 * of IPFIXcol internal message pipeline.
 *
 * @{
 */

/** Internal ring buffer type  */
struct IPX_API ipx_ring;
typedef struct ipx_ring ipx_ring_t;

/**
 * \brief Create a new ring buffer
 *
 * \note If \p mw_mode is disabled and multiple writers try to write into the buffer at the same
 *   time, result is undefined!
 * \note Enabling \p mw_mode has significant impact on performance in case the protection is not
 *   necessary.
 * \param[in] size    Size of the ring buffer (number of pointers)
 * \param[in] mw_mode Multi-writer mode (multiple writers can writer into the buffer)
 * \return A pointer to the buffer or NULL (in case of an error).
 */
IPX_API ipx_ring_t* ipx_ring_init(uint32_t size, bool mw_mode);

/**
 * \brief A ring buffer to destroy
 * \param[in] ring
 */
IPX_API void ipx_ring_destroy(ipx_ring_t* ring);

/**
 * \brief Add a message into the ring buffer
 *
 * Multiple threads can use this function at the same time to add messages if the multi-writer
 * mode has been enabled during the ring initialization. Otherwise, result of concurrent adding
 * is not defined.
 * \note The function blocks until the message is added.
 * \param[in] ring Ring buffer
 * \param[in] msg  Message to be added into the ring buffer
 */
IPX_API void ipx_ring_push(ipx_ring_t* ring, ipx_msg_t* msg);

/**
 * \brief Get a message from the ring buffer
 *
 * \note The function blocks until the message is ready.
 * \warning Cannot be used concurrently by multiple threads at the same time.
 * \param[in] ring Ring buffer
 * \return Pointer to the message
 */
IPX_API ipx_msg_t* ipx_ring_pop(ipx_ring_t* ring);

/**
 * \brief Change (i.e. disable/enable) multi-writer mode
 *
 * \warning
 *   During this function call, the user MUST make sure that nobody is pushing messages to the
 *   buffer. Otherwise it can cause deadlock!
 * \param[in] ring Ring buffer
 * \param[in] mode New mode
 */
IPX_API void ipx_ring_mw_mode(ipx_ring_t* ring, bool mode);

IPX_API uint32_t ipx_ring_cnt(const ipx_ring_t* ring);

IPX_API uint32_t ipx_ring_size(const ipx_ring_t* ring);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif
#endif // IPX_RING_H
