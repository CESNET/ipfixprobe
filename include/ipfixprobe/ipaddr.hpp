/**
 * \file ipaddr.hpp
 * \brief Structure for storage of IPv4 or IPv6 address.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
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
 *
 *
 *
 */

#ifndef IPXP_IPADDR_HPP
#define IPXP_IPADDR_HPP

namespace ipxp {

enum IP : uint8_t {
   v4 = 4,
   v6 = 6
};

/**
 * \brief Store IPv4 or IPv6 address.
 */
typedef union ipaddr_u {
   uint8_t  v6[16];  /**< IPv6 address. */
   uint32_t v4;      /**< IPv4 address  */
} ipaddr_t;

}
#endif /* IPXP_IPADDR_HPP */
