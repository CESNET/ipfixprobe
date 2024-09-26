/**
 * \file ipfix-basiclist.hpp
 * \brief struct representing ipfix basiclist fmt
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
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

#ifndef IPFIXBASICLIST
#define IPFIXBASICLIST

#include <arpa/inet.h>
#include <sys/time.h>
#include <cstring>
#include <ipfixprobe/byte-utils.hpp>

namespace ipxp {

struct IpfixBasicList {
public:
   static const uint8_t IpfixBasicListRecordHdrSize = 12;
   static const uint8_t IpfixBasicListHdrSize       = 9;
   static const uint8_t flag        = 255; // Maximum size see rfc631;
   static const uint8_t hdrSemantic = 3;

   enum ePEMNumber {
      CesnetPEM = 8057,
   };

   ePEMNumber hdrEnterpriseNum;


   static uint64_t Tv2Ts(timeval input);

   int32_t HeaderSize();
   int32_t FillBuffer(uint8_t *buffer, uint16_t *values, uint16_t len, uint16_t fieldID);
   int32_t FillBuffer(uint8_t *buffer, int16_t *values, uint16_t len, uint16_t fieldID);
   int32_t FillBuffer(uint8_t *buffer, uint32_t *values, uint16_t len, uint16_t fieldID);
   int32_t FillBuffer(uint8_t *buffer, int32_t *values, uint16_t len, uint16_t fieldID);
   int32_t FillBuffer(uint8_t *buffer, struct timeval *values, uint16_t len, uint16_t fieldID);
   int32_t FillBuffer(uint8_t *buffer, uint8_t *values, uint16_t len, uint16_t fieldID);
   int32_t FillBuffer(uint8_t *buffer, int8_t *values, uint16_t len, uint16_t fieldID);

private:
   int32_t FillBufferHdr(uint8_t *buffer, uint16_t length, uint16_t elementLength, uint16_t fieldID);
};

}
#endif // ifndef IPFIXBASICLIST
